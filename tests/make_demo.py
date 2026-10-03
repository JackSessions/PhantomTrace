"""Creates demo/clean.img and demo/tampered.img so you can try the tool in seconds (needs mkntfs + ntfscp)."""
import os
import shutil
import images

os.makedirs("demo", exist_ok=True)
images.build_clean("demo/clean.img")
shutil.copy("demo/clean.img", "demo/tampered.img")
images.tamper_bitmap_free("demo/tampered.img", "file1.bin")
images.tamper_flag_flip("demo/tampered.img", "file2.bin")
images.tamper_cross_alloc("demo/tampered.img", "file3.bin", "file5.bin")
images.tamper_torn("demo/tampered.img", "file4.bin")
print("created demo/clean.img and demo/tampered.img")
