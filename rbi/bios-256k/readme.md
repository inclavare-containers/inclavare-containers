# RB for bios-256k.bin

## files

`build-docker-image.sh` To build RBCI for bios
`build-bios.sh` To build bios and check artifest

## Steps

Build RBCI for bios.
```
./build-docker-image.sh
```

reproducible build bios and generate report
```
./build-bios.sh . ../result/bios
``` 

If correctly, you can get report as
```plaintext
$cat ../result/bios/report 
===bios-256k.bin RB Test===
[Time] 2021-07-31 10:01:07
[Succeed] Same hash 48772e82a2993f44894820637ce13e0aceb9ab68d3b01dab79c945eaaa2d74cf
```