SUBDIRS += hw/ast-bmc

AST_BMC_OBJS  = ast-io.o ast2400-sf-ctrl.o
AST_BMC = hw/ast-bmc/built-in.o
$(AST_BMC): $(AST_BMC_OBJS:%=hw/ast-bmc/%)
