/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <skiboot.h>
#include <opal.h>
#include <chip.h>
#include <sensor.h>
#include <device.h>
#include <cpu.h>

/*
 * OCC Sensor Data
 *
 * OCC sensor data will use BAR2 (OCC Common is per physical drawer).
 * Starting address is at offset 0x00580000 from BAR2 base address.
 * Maximum size is 1.5MB.
 *
 * -------------------------------------------------------------------------
 * | Start (Offset from |	End	| Size	   |Description		   |
 * | BAR2 base address) |		|	   |			   |
 * -------------------------------------------------------------------------
 * |	0x00580000      |  0x005A57FF   |150kB     |OCC 0 Sensor Data Block|
 * |	0x005A5800      |  0x005CAFFF   |150kB	   |OCC 1 Sensor Data Block|
 * |	    :		|	:	|  :	   |		:          |
 * |	0x00686800	|  0x006ABFFF   |150kB	   |OCC 7 Sensor Data Block|
 * |	0x006AC000	|  0x006FFFFF   |336kB     |Reserved		   |
 * -------------------------------------------------------------------------
 *
 *
 * OCC N Sensor Data Block Layout (150kB)
 *
 * The sensor data block layout is the same for each OCC N. It contains
 * sensor-header-block, sensor-names buffer, sensor-readings-ping buffer and
 * sensor-readings-pong buffer.
 *
 * ----------------------------------------------------------------------------
 * | Start (Offset from OCC |   End	   | Size |Description		      |
 * | N Sensor Data Block)   |		   |	  |			      |
 * ----------------------------------------------------------------------------
 * |	0x00000000	    |  0x000003FF  |1kB   |Sensor Data Header Block   |
 * |	0x00000400	    |  0x0000CBFF  |50kB  |Sensor Names		      |
 * |	0x0000CC00	    |  0x0000DBFF  |4kB   |Reserved		      |
 * |	0x0000DC00	    |  0x00017BFF  |40kB  |Sensor Readings ping buffer|
 * |	0x00017C00	    |  0x00018BFF  |4kB   |Reserved		      |
 * |	0x00018C00	    |  0x00022BFF  |40kB  |Sensor Readings pong buffer|
 * |	0x00022C00	    |  0x000257FF  |11kB  |Reserved		      |
 * ----------------------------------------------------------------------------
 *
 * Sensor Data Header Block : This is written once by the OCC during
 * initialization after a load or reset. Layout is defined in 'struct
 * occ_sensor_data_header'
 *
 * Sensor Names : This is written once by the OCC during initialization after a
 * load or reset. It contains static information for each sensor. The number of
 * sensors, format version and length of each sensor is defined in
 * 'Sensor Data Header Block'. Format of each sensor name is defined in
 * 'struct occ_sensor_name'. The first sensor starts at offset 0 followed
 * immediately by the next sensor.
 *
 * Sensor Readings Ping/Pong Buffer:
 * There are two 40kB buffers to store the sensor readings. One buffer that
 * is currently being updated by the OCC and one that is available to be read.
 * Each of these buffers will be of the same format. The number of sensors and
 * the format version of the ping and pong buffers is defined in the
 * 'Sensor Data Header Block'.
 *
 * Each sensor within the ping and pong buffers may be of a different format
 * and length. For each sensor the length and format is determined by its
 * 'struct occ_sensor_name.structure_type' in the Sensor Names buffer.
 *
 * --------------------------------------------------------------------------
 * | Offset | Byte0 | Byte1 | Byte2 | Byte3 | Byte4 | Byte5 | Byte6 | Byte7 |
 * --------------------------------------------------------------------------
 * | 0x0000 |Valid  |		   Reserved				    |
 * |        |(0x01) |							    |
 * --------------------------------------------------------------------------
 * | 0x0008 |			Sensor Readings				    |
 * --------------------------------------------------------------------------
 * |	:   |				:				    |
 * --------------------------------------------------------------------------
 * | 0xA000 |                     End of Data				    |
 * --------------------------------------------------------------------------
 *
 */

#define MAX_OCCS			8
#define MAX_CHARS_SENSOR_NAME		16
#define MAX_CHARS_SENSOR_UNIT		4

#define OCC_SENSOR_DATA_BLOCK_OFFSET		0x00580000
#define OCC_SENSOR_DATA_BLOCK_SIZE		0x00025800

/*
 * These should match the definitions inside the OCC source:
 * occ/src/occ_405/sensor/sensor_info.c
 */

enum occ_sensor_type {
	OCC_SENSOR_TYPE_GENERIC		= 0x0001,
	OCC_SENSOR_TYPE_CURRENT		= 0x0002,
	OCC_SENSOR_TYPE_VOLTAGE		= 0x0004,
	OCC_SENSOR_TYPE_TEMPERATURE	= 0x0008,
	OCC_SENSOR_TYPE_UTILIZATION	= 0x0010,
	OCC_SENSOR_TYPE_TIME		= 0x0020,
	OCC_SENSOR_TYPE_FREQUENCY	= 0x0040,
	OCC_SENSOR_TYPE_POWER		= 0x0080,
	OCC_SENSOR_TYPE_PERFORMANCE	= 0x0200,
};

enum occ_sensor_location {
	OCC_SENSOR_LOC_SYSTEM		= 0x0001,
	OCC_SENSOR_LOC_PROCESSOR	= 0x0002,
	OCC_SENSOR_LOC_PARTITION	= 0x0004,
	OCC_SENSOR_LOC_MEMORY		= 0x0008,
	OCC_SENSOR_LOC_VRM		= 0x0010,
	OCC_SENSOR_LOC_OCC		= 0x0020,
	OCC_SENSOR_LOC_CORE		= 0x0040,
	OCC_SENSOR_LOC_GPU		= 0x0080,
	OCC_SENSOR_LOC_QUAD		= 0x0100,
};

enum sensor_struct_type {
	OCC_SENSOR_READING_FULL		= 0x01,
	OCC_SENSOR_READING_COUNTER	= 0x02,
};

/**
 * struct occ_sensor_data_header -	Sensor Data Header Block
 * @valid:				When the value is 0x01 it indicates
 *					that this header block and the sensor
 *					names buffer are ready
 * @version:				Format version of this block
 * @nr_sensors:				Number of sensors in names, ping and
 *					pong buffer
 * @reading_version:			Format version of the Ping/Pong buffer
 * @names_offset:			Offset to the location of names buffer
 * @names_version:			Format version of names buffer
 * @names_length:			Length of each sensor in names buffer
 * @reading_ping_offset:		Offset to the location of Ping buffer
 * @reading_pong_offset:		Offset to the location of Pong buffer
 * @pad/reserved:			Unused data
 */
struct occ_sensor_data_header {
	u8 valid;
	u8 version;
	u16 nr_sensors;
	u8 reading_version;
	u8 pad[3];
	u32 names_offset;
	u8 names_version;
	u8 name_length;
	u16 reserved;
	u32 reading_ping_offset;
	u32 reading_pong_offset;
} __packed;

/**
 * struct occ_sensor_name -		Format of Sensor Name
 * @name:				Sensor name
 * @units:				Sensor units of measurement
 * @gsid:				Global sensor id (OCC)
 * @freq:				Update frequency
 * @scale_factor:			Scaling factor
 * @type:				Sensor type as defined in
 *					'enum occ_sensor_type'
 * @location:				Sensor location as defined in
 *					'enum occ_sensor_location'
 * @structure_type:			Indicates type of data structure used
 *					for the sensor readings in the ping and
 *					pong buffers for this sensor as defined
 *					in 'enum sensor_struct_type'
 * @reading_offset:			Offset from the start of the ping/pong
 *					reading buffers for this sensor
 * @sensor_data:			Sensor specific info
 * @pad:				Padding to fit the size of 48 bytes.
 */
struct occ_sensor_name {
	char name[MAX_CHARS_SENSOR_NAME];
	char units[MAX_CHARS_SENSOR_UNIT];
	u16 gsid;
	u32 freq;
	u32 scale_factor;
	u16 type;
	u16 location;
	u8 structure_type;
	u32 reading_offset;
	u8 sensor_data;
	u8 pad[8];
} __packed;

/**
 * struct occ_sensor_record -		Sensor Reading Full
 * @gsid:				Global sensor id (OCC)
 * @timestamp:				Time base counter value while updating
 *					the sensor
 * @sample:				Latest sample of this sensor
 * @sample_min:				Minimum value since last OCC reset
 * @sample_max:				Maximum value since last OCC reset
 * @csm_min:				Minimum value since last reset request
 *					by CSM (CORAL)
 * @csm_max:				Maximum value since last reset request
 *					by CSM (CORAL)
 * @profiler_min:			Minimum value since last reset request
 *					by profiler (CORAL)
 * @profiler_max:			Maximum value since last reset request
 *					by profiler (CORAL)
 * @job_scheduler_min:			Minimum value since last reset request
 *					by job scheduler(CORAL)
 * @job_scheduler_max:			Maximum value since last reset request
 *					by job scheduler (CORAL)
 * @accumulator:			Accumulator for this sensor
 * @update_tag:				Count of the number of ticks that have
 *					passed between updates
 * @pad:				Padding to fit the size of 48 bytes
 */
struct occ_sensor_record {
	u16 gsid;
	u64 timestamp;
	u16 sample;
	u16 sample_min;
	u16 sample_max;
	u16 csm_min;
	u16 csm_max;
	u16 profiler_min;
	u16 profiler_max;
	u16 job_scheduler_min;
	u16 job_scheduler_max;
	u64 accumulator;
	u32 update_tag;
	u8 pad[8];
} __packed;

/**
 * struct occ_sensor_counter -		Sensor Reading Counter
 * @gsid:				Global sensor id (OCC)
 * @timestamp:				Time base counter value while updating
 *					the sensor
 * @accumulator:			Accumulator/Counter
 * @sample:				Latest sample of this sensor (0/1)
 * @pad:				Padding to fit the size of 24 bytes
 */
struct occ_sensor_counter {
	u16 gsid;
	u64 timestamp;
	u64 accumulator;
	u8 sample;
	u8 pad[5];
} __packed;

enum sensor_attr {
	SENSOR_SAMPLE,
	SENSOR_SAMPLE_MIN,	/* OCC's min/max */
	SENSOR_SAMPLE_MAX,
	SENSOR_CSM_MIN,		/* CSM's min/max */
	SENSOR_CSM_MAX,
	SENSOR_ACCUMULATOR,
	MAX_SENSOR_ATTR,
};

#define HWMON_SENSORS_MASK	(OCC_SENSOR_TYPE_CURRENT | \
				 OCC_SENSOR_TYPE_VOLTAGE | \
				 OCC_SENSOR_TYPE_TEMPERATURE | \
				 OCC_SENSOR_TYPE_POWER)

/*
 * Standard HWMON linux interface expects the below units for the
 * environment sensors:
 * - Current		: milliampere
 * - Voltage		: millivolt
 * - Temperature	: millidegree Celsius (scaled in kernel)
 * - Power		: microWatt	      (scaled in kernel)
 * - Energy		: microJoule
 */

/*
 * OCC sensor units are obtained after scaling the sensor values.
 * https://github.com/open-power/occ/blob/master/src/occ_405/sensor/sensor_info.c
 */

static struct str_map {
	const char *occ_str;
	const char *opal_str;
} str_maps[] = {
	{"PWRSYS", "System"},
	/* Bulk power of the system: Watt */
	{"PWRFAN", "Fan"},
	/* Power consumption of the system fans: Watt */
	{"PWRIO", "IO"},
	/* Power consumption of the IO subsystem: Watt */
	{"PWRSTORE", "Storage"},
	/* Power comsumption of the storage subsystem: Watt */
	{"PWRGPU", "GPU"},
	/* Power consumption for GPUs per socket read from APSS: Watt */
	{"PWRAPSSCH", "APSS"},
	/* Power Provided by APSS channel x (where x=0…15): Watt */
	{"PWRPROC", ""},
	/* Power consumption for this Processor: Watt */
	{"PWRVDD", "Vdd"},
	/* Power consumption for this Processor's Vdd(AVSBus readings): Watt */
	{"PWRVDN", "Vdn"},
	/* Power consumption for  this Processor's Vdn (nest)
	 * Calculated from AVSBus readings: Watt */
	{"PWRMEM", "Memory"},
	/* Power consumption for Memory  for this Processor read from APSS:
	 * Watt */
	{"CURVDD", "Vdd"},
	/* Processor Vdd Current (read from AVSBus): Ampere */
	{"CURVDN", "Vdn"},
	/* Processor Vdn Current (read from AVSBus): Ampere */
	{"VOLTVDDSENSE", "Vdd Remote Sense"},
	/* Vdd Voltage at the remote sense.
	 * AVS reading adjusted for loadline: millivolt */
	{"VOLTVDNSENSE", "Vdn Remote Sense"},
	/* Vdn Voltage at the remote sense.
	 * AVS reading adjusted for loadline: millivolt */
	{"VOLTVDD", "Vdd"},
	/* Processor Vdd Voltage (read from AVSBus): millivolt */
	{"VOLTVDN", "Vdn"},
	/* Processor Vdn Voltage (read from AVSBus): millivolt */
	{"TEMPC", "Core"},
	/* Average temperature of core DTS sensors for Processor's Core y:
	 * Celsius */
	{"TEMPQ", "Quad"},
	/* Average temperature of quad (in cache) DTS sensors for
	 * Processor’s Quad y: Celsius */
	{"TEMPNEST", "Nest"},
	/* Average temperature of nest DTS sensors: Celsius */
	{"TEMPPROCTHRMC", "Core"},
	/* The combined weighted core/quad temperature for processor core y:
	 * Celsius */
	{"TEMPDIMM", "DIMM"},
	/* DIMM temperature for DIMM x: Celsius */
	{"TEMPGPU", "GPU"},
	/* GPU x (0..2) board temperature: Celsius */
	/* TEMPGPUxMEM: GPU x hottest HBM temperature (individual memory
	 * temperatures are not available): Celsius */
	{"TEMPVDD", "VRM VDD"},
	/* VRM Vdd temperature: Celsius */
};

static u64 occ_sensor_base;

static inline
struct occ_sensor_data_header *get_sensor_header_block(int occ_num)
{
	return (struct occ_sensor_data_header *)
		(occ_sensor_base + occ_num * OCC_SENSOR_DATA_BLOCK_SIZE);
}

static inline
struct occ_sensor_name *get_names_block(struct occ_sensor_data_header *hb)
{
	return ((struct occ_sensor_name *)((u64)hb + hb->names_offset));
}

static inline u32 sensor_handler(int occ_num, int sensor_id, int attr)
{
	return sensor_make_handler(SENSOR_OCC, occ_num, sensor_id, attr);
}

/*
 * The scaling factor for the sensors is encoded in the below format:
 * (((UINT32)mantissa << 8) | (UINT32)((UINT8) 256 + (UINT8)exp))
 * https://github.com/open-power/occ/blob/master/src/occ_405/sensor/sensor.h
 */
static void scale_sensor(struct occ_sensor_name *md, u64 *sensor)
{
	u32 factor = md->scale_factor;
	int i;
	s8 exp;

	if (md->type == OCC_SENSOR_TYPE_CURRENT)
		*sensor *= 1000; //convert to mA

	*sensor *= factor >> 8;
	exp = factor & 0xFF;

	if (exp > 0) {
		for (i = labs(exp); i > 0; i--)
			*sensor *= 10;
	} else {
		for (i = labs(exp); sensor && i > 0; i--)
			*sensor /= 10;
	}
}

static void scale_energy(struct occ_sensor_name *md, u64 *sensor)
{
	u32 factor = md->freq;
	int i;
	s8 exp;

	*sensor *= 1000000; //convert to uJ

	*sensor /= factor >> 8;
	exp = factor & 0xFF;

	if (exp > 0) {
		for (i = labs(exp); sensor && i > 0; i--)
			*sensor /= 10;
	} else {
		for (i = labs(exp); i > 0; i--)
			*sensor *= 10;
	}
}

static u64 read_sensor(struct occ_sensor_record *sensor, int attr)
{
	switch (attr) {
	case SENSOR_SAMPLE:
		return sensor->sample;
	case SENSOR_SAMPLE_MIN:
		return sensor->sample_min;
	case SENSOR_SAMPLE_MAX:
		return sensor->sample_max;
	case SENSOR_CSM_MIN:
		return sensor->csm_min;
	case SENSOR_CSM_MAX:
		return sensor->csm_max;
	case SENSOR_ACCUMULATOR:
		return sensor->accumulator;
	default:
		break;
	}

	return 0;
}

static void *select_sensor_buffer(struct occ_sensor_data_header *hb, int id)
{
	struct occ_sensor_name *md;
	u8 *ping, *pong;
	void *buffer = NULL;

	if (!hb)
		return NULL;

	md = get_names_block(hb);

	ping = (u8 *)((u64)hb + hb->reading_ping_offset);
	pong = (u8 *)((u64)hb + hb->reading_pong_offset);

	/* Check which buffer is valid  and read the data from that.
	 * Ping Pong	Action
	 *  0	0	Return with error
	 *  0	1	Read Pong
	 *  1	0	Read Ping
	 *  1	1	Read the buffer with latest timestamp
	 */

	if (*ping && *pong) {
		u64 tping, tpong;
		u64 ping_buf = (u64)ping + md[id].reading_offset;
		u64 pong_buf = (u64)pong + md[id].reading_offset;

		tping = ((struct occ_sensor_record *)ping_buf)->timestamp;
		tpong = ((struct occ_sensor_record *)pong_buf)->timestamp;

		if (tping > tpong)
			buffer = ping;
		else
			buffer = pong;
	} else if (*ping && !*pong) {
		buffer = ping;
	} else if (!*ping && *pong) {
		buffer = pong;
	} else if (!*ping && !*pong) {
		prlog(PR_DEBUG, "OCC: Both ping and pong sensor buffers are invalid\n");
		return NULL;
	}

	assert(buffer);
	buffer = (void *)((u64)buffer + md[id].reading_offset);

	return buffer;
}

int occ_sensor_read(u32 handle, u64 *data)
{
	struct occ_sensor_data_header *hb;
	struct occ_sensor_name *md;
	u16 id = sensor_get_rid(handle);
	u8 occ_num = sensor_get_frc(handle);
	u8 attr = sensor_get_attr(handle);
	void *buff;

	if (occ_num > MAX_OCCS)
		return OPAL_PARAMETER;

	if (attr > MAX_SENSOR_ATTR)
		return OPAL_PARAMETER;

	hb = get_sensor_header_block(occ_num);

	if (hb->valid != 1)
		return OPAL_HARDWARE;

	if (id > hb->nr_sensors)
		return OPAL_PARAMETER;

	buff = select_sensor_buffer(hb, id);
	if (!buff)
		return OPAL_HARDWARE;

	*data = read_sensor(buff, attr);
	if (!*data)
		return OPAL_SUCCESS;

	md = get_names_block(hb);
	if (md[id].type == OCC_SENSOR_TYPE_POWER && attr == SENSOR_ACCUMULATOR)
		scale_energy(&md[id], data);
	else
		scale_sensor(&md[id], data);

	return OPAL_SUCCESS;
}

static bool occ_sensor_sanity(struct occ_sensor_data_header *hb, int chipid)
{
	if (hb->valid != 0x01) {
		prerror("OCC: Chip %d sensor data invalid\n", chipid);
		return false;
	}

	if (hb->version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor header block version %d\n",
			chipid, hb->version);
		return false;
	}

	if (hb->reading_version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor record format %d\n",
			chipid, hb->reading_version);
		return false;
	}

	if (hb->names_version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor names format %d\n",
			chipid, hb->names_version);
		return false;
	}

	if (hb->name_length != sizeof(struct occ_sensor_name)) {
		prerror("OCC: Chip %d unsupported sensor names length %d\n",
			chipid, hb->name_length);
		return false;
	}

	if (!hb->nr_sensors) {
		prerror("OCC: Chip %d has no sensors\n", chipid);
		return false;
	}

	if (!hb->names_offset || !hb->reading_ping_offset ||
	    !hb->reading_pong_offset) {
		prerror("OCC: Chip %d Invalid sensor buffer pointers\n",
			chipid);
		return false;
	}

	return true;
}

/*
 * parse_entity: Parses OCC sensor name to return the entity number like
 *		 chipid, core-id, dimm-no, gpu-no. 'end' is used to
 *		 get the subentity strings. Returns -1 if no number is found.
 *		 TEMPC4 --> returns 4, end will be NULL
 *		 TEMPGPU2DRAM1 --> returns 2, end = "DRAM1"
 *		 PWRSYS --> returns -1, end = NULL
 */
static int parse_entity(const char *name, char **end)
{
	while (*name != '\0') {
		if (isdigit(*name))
			break;
		name++;
	}

	if (*name)
		return strtol(name, end, 10);
	else
		return -1;
}

static void add_sensor_label(struct dt_node *node, struct occ_sensor_name *md,
			     int chipid)
{
	char sname[30] = "";
	char prefix[30] = "";
	int i;

	if (md->location != OCC_SENSOR_LOC_SYSTEM)
		snprintf(prefix, sizeof(prefix), "%s %d ", "Chip", chipid);

	for (i = 0; i < ARRAY_SIZE(str_maps); i++)
		if (!strncmp(str_maps[i].occ_str, md->name,
			     strlen(str_maps[i].occ_str))) {
			char *end;
			int num = -1;

			if (md->location != OCC_SENSOR_LOC_CORE)
				num = parse_entity(md->name, &end);

			if (num != -1) {
				snprintf(sname, sizeof(sname), "%s%s %d %s",
					 prefix, str_maps[i].opal_str, num,
					 end);
			} else {
				snprintf(sname, sizeof(sname), "%s%s", prefix,
					 str_maps[i].opal_str);
			}
			dt_add_property_string(node, "label", sname);
			return;
		}

	/* Fallback to OCC literal if mapping is not found */
	if (md->location == OCC_SENSOR_LOC_SYSTEM) {
		dt_add_property_string(node, "label", md->name);
	} else {
		snprintf(sname, sizeof(sname), "%s%s", prefix, md->name);
		dt_add_property_string(node, "label", sname);
	}
}

static const char *get_sensor_type_string(enum occ_sensor_type type)
{
	switch (type) {
	case OCC_SENSOR_TYPE_POWER:
		return "power";
	case OCC_SENSOR_TYPE_TEMPERATURE:
		return "temp";
	case OCC_SENSOR_TYPE_CURRENT:
		return "curr";
	case OCC_SENSOR_TYPE_VOLTAGE:
		return "in";
	default:
		break;
	}

	return "unknown";
}

static const char *get_sensor_loc_string(enum occ_sensor_location loc)
{
	switch (loc) {
	case OCC_SENSOR_LOC_SYSTEM:
		return "sys";
	case OCC_SENSOR_LOC_PROCESSOR:
		return "proc";
	case OCC_SENSOR_LOC_MEMORY:
		return "mem";
	case OCC_SENSOR_LOC_VRM:
		return "vrm";
	case OCC_SENSOR_LOC_CORE:
		return "core";
	case OCC_SENSOR_LOC_QUAD:
		return "quad";
	case OCC_SENSOR_LOC_GPU:
		return "gpu";
	default:
		break;
	}

	return "unknown";
}

/*
 * Power sensors can be 0 valued in few platforms like Zaius, Romulus
 * which do not have APSS. At the moment there is no HDAT/DT property
 * to indicate if APSS is present. So for now skip zero valued power
 * sensors.
 */
static bool check_sensor_sample(struct occ_sensor_data_header *hb, u32 offset)
{
	struct occ_sensor_record *ping, *pong;

	ping = (struct occ_sensor_record *)((u64)hb + hb->reading_ping_offset
					     + offset);
	pong = (struct occ_sensor_record *)((u64)hb + hb->reading_pong_offset
					     + offset);
	return ping->sample || pong->sample;
}

static void add_sensor_node(const char *loc, const char *type, int i, int attr,
			    struct occ_sensor_name *md, u32 *phandle, u32 pir,
			    u32 occ_num, u32 chipid)
{
	char name[30];
	struct dt_node *node;
	u32 handler;

	snprintf(name, sizeof(name), "%s-%s", loc, type);
	handler = sensor_handler(occ_num, i, attr);
	node = dt_new_addr(sensor_node, name, handler);
	dt_add_property_string(node, "sensor-type", type);
	dt_add_property_cells(node, "sensor-data", handler);
	dt_add_property_cells(node, "reg", handler);
	dt_add_property_string(node, "occ_label", md->name);
	add_sensor_label(node, md, chipid);

	if (md->location == OCC_SENSOR_LOC_CORE)
		dt_add_property_cells(node, "ibm,pir", pir);

	if (attr == SENSOR_SAMPLE) {
		handler = sensor_handler(occ_num, i, SENSOR_CSM_MAX);
		dt_add_property_cells(node, "sensor-data-max", handler);

		handler = sensor_handler(occ_num, i, SENSOR_CSM_MIN);
		dt_add_property_cells(node, "sensor-data-min", handler);
	}

	dt_add_property_string(node, "compatible", "ibm,opal-sensor");
	*phandle = node->phandle;
}

void occ_sensors_init(void)
{
	struct proc_chip *chip;
	struct dt_node *sg, *exports;
	int occ_num = 0, i;
	bool has_gpu = false;

	/* OCC inband sensors is only supported in P9 */
	if (proc_gen != proc_gen_p9)
		return;

	/* Sensors are copied to BAR2 OCC Common Area */
	chip = next_chip(NULL);
	if (!chip->occ_common_base) {
		prerror("OCC: Unassigned OCC Common Area. No sensors found\n");
		return;
	}

	occ_sensor_base = chip->occ_common_base + OCC_SENSOR_DATA_BLOCK_OFFSET;

	sg = dt_new(opal_node, "sensor-groups");
	if (!sg) {
		prerror("OCC: Failed to create sensor groups node\n");
		return;
	}
	dt_add_property_string(sg, "compatible", "ibm,opal-sensor-group");
	dt_add_property_cells(sg, "#address-cells", 1);
	dt_add_property_cells(sg, "#size-cells", 0);

	if (dt_find_compatible_node(dt_root, NULL, "ibm,power9-npu"))
		has_gpu = true;

	for_each_chip(chip) {
		struct occ_sensor_data_header *hb;
		struct occ_sensor_name *md;
		u32 *phandles, phcount = 0;

		hb = get_sensor_header_block(occ_num);
		md = get_names_block(hb);

		/* Sanity check of the Sensor Data Header Block */
		if (!occ_sensor_sanity(hb, chip->id))
			continue;

		phandles = malloc(hb->nr_sensors * sizeof(u32));
		assert(phandles);

		for (i = 0; i < hb->nr_sensors; i++) {
			const char *type, *loc;
			struct cpu_thread *c = NULL;

			if (md[i].structure_type != OCC_SENSOR_READING_FULL)
				continue;

			if (!(md[i].type & HWMON_SENSORS_MASK))
				continue;

			if (md[i].location == OCC_SENSOR_LOC_GPU && !has_gpu)
				continue;

			if (md[i].type == OCC_SENSOR_TYPE_POWER &&
			    !check_sensor_sample(hb, md[i].reading_offset))
				continue;

			if (md[i].location == OCC_SENSOR_LOC_CORE) {
				int num = parse_entity(md[i].name, NULL);

				for_each_available_core_in_chip(c, chip->id)
					if (pir_to_core_id(c->pir) == num)
						break;
				if (!c)
					continue;
			}

			type = get_sensor_type_string(md[i].type);
			loc = get_sensor_loc_string(md[i].location);

			add_sensor_node(loc, type, i, SENSOR_SAMPLE, &md[i],
					&phandles[phcount], c->pir, occ_num,
					chip->id);
			phcount++;

			/* Add energy sensors */
			if (md[i].type == OCC_SENSOR_TYPE_POWER &&
			    md[i].structure_type == OCC_SENSOR_READING_FULL) {
				add_sensor_node(loc, "energy", i,
						SENSOR_ACCUMULATOR, &md[i],
						&phandles[phcount], c->pir,
						occ_num, chip->id);
				phcount++;
			}

		}
		occ_num++;
		occ_add_sensor_groups(sg, phandles, phcount, chip->id);
		free(phandles);
	}

	if (!occ_num)
		return;

	exports = dt_find_by_path(dt_root, "/ibm,opal/firmware/exports");
	if (!exports) {
		prerror("OCC: dt node /ibm,opal/firmware/exports not found\n");
		return;
	}

	dt_add_property_u64s(exports, "occ_inband_sensors", occ_sensor_base,
			     OCC_SENSOR_DATA_BLOCK_SIZE * occ_num);
}
