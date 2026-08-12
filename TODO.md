# Storage Error Injection — Protocol-level Support

[DONE] USB Mass Storage — expose internal SCSI device to existing injection hooks
[DONE] UFS — add SCSI CDB injection hooks to hw/ufs/lu.c (SCSI internally)
[ ] NVMe — inject Identify Controller/Namespace responses and status codes in hw/nvme/ctrl.c
[ ] ATA/SATA — inject IDENTIFY DEVICE, SMART data, and ATA error registers in hw/ide/core.c
[ ] SD/MMC — inject CID/CSD responses and status/error codes in hw/sd/sd.c
