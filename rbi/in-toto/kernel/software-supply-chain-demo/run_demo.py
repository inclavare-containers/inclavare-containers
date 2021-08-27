import os
import sys
import shlex
import subprocess
import argparse
import time
import pathlib
from shutil import copyfile, copytree, rmtree

try:
  input = raw_input
except NameError:
  pass

NO_PROMPT = False

def prompt_key(prompt):
  if NO_PROMPT:
    print("\n" + prompt)
    return
  inp = False
  while inp != "":
    try:
      inp = input("\n{} -- press any key to continue".format(prompt))
    except Exception:
      pass

def supply_chain():

  prompt_key("Define supply chain layout (Jerry)")
  os.chdir("owner_jerry")
  create_layout_cmd = "python create_layout.py"
  print(create_layout_cmd)
  subprocess.call(shlex.split(create_layout_cmd))

  prompt_key("Clone source code (Alice)")
  os.chdir("../functionary_alice")
  clone_cmd = ("in-toto-run"
                    " --step-name clone"
                    " --products inclavare-containers/rbi/kernel/Dockerfile"
                    " inclavare-containers/rbi/kernel/build-docker-image.sh"
                    " inclavare-containers/rbi/kernel/build-kernel.sh"
                    " inclavare-containers/rbi/kernel/check-integrity.sh"
                    " inclavare-containers/rbi/kernel/patch/build-kernel.sh"
                    " inclavare-containers/rbi/kernel/scripts/start.sh"
                    " inclavare-containers/rbi/misc/check-integrity.sh"
                    " --key alice"
                    " -- git clone https://github.com/alibaba/inclavare-containers.git")
  print(clone_cmd)
  print("This process may take a while..")
  subprocess.call(shlex.split(clone_cmd))

  prompt_key("Build (Bob)")
  os.chdir("../functionary_bob")
  copytree("../functionary_alice/inclavare-containers", "inclavare-containers")
  build_cmd = ("in-toto-run"
                    " --step-name build"
                    " --materials inclavare-containers/rbi/kernel/Dockerfile"
                    " inclavare-containers/rbi/kernel/build-docker-image.sh"
                    " inclavare-containers/rbi/kernel/build-kernel.sh"
                    " inclavare-containers/rbi/kernel/check-integrity.sh"
                    " inclavare-containers/rbi/kernel/patch/build-kernel.sh"
                    " inclavare-containers/rbi/kernel/scripts/start.sh"
                    " inclavare-containers/rbi/misc/check-integrity.sh"
                    " --products inclavare-containers/rbi/result/kernel/vmlinux"
                    " --key bob -- bash inclavare-containers/rbi/rbi.sh kernel")

  print(build_cmd)
  print("This process may take about 10 minute..")
  subprocess.call(shlex.split(build_cmd))

  prompt_key("Create final product")
  os.chdir("..")
  copyfile("owner_jerry/root.layout", "final_product/root.layout")
  copyfile("functionary_alice/clone.3b1a98aa.link", "final_product/clone.3b1a98aa.link")
  copyfile("functionary_bob/build.f6701b1e.link", "final_product/build.f6701b1e.link")
  pathlib.Path("final_product/inclavare-containers/rbi/misc").mkdir(parents = True, exist_ok = True)
  pathlib.Path("final_product/inclavare-containers/rbi/result/kernel").mkdir(parents = True, exist_ok = True)
  copyfile("functionary_bob/inclavare-containers/rbi/misc/check-integrity.sh", "final_product/inclavare-containers/rbi/misc/check-integrity.sh")
  copyfile("functionary_bob/inclavare-containers/rbi/result/kernel/vmlinux", "final_product/inclavare-containers/rbi/result/kernel/vmlinux")

  prompt_key("Verify final product (client)")
  os.chdir("final_product")
  copyfile("../owner_jerry/jerry.pub", "jerry.pub")
  verify_cmd = ("in-toto-verify"
                " --verbose"
                " --layout root.layout"
                " --layout-key jerry.pub")
  print(verify_cmd)
  retval = subprocess.call(shlex.split(verify_cmd))
  print("Return value: " + str(retval))

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-n", "--no-prompt", help="No prompt.",
      action="store_true")
  parser.add_argument("-c", "--clean", help="Remove files created during demo.",
      action="store_true")
  args = parser.parse_args()

  if args.clean:
    files_to_delete = [
      "owner_jerry/root.layout",
      "functionary_alice/clone.3b1a98aa.link",
      "functionary_alice/inclavare-containers",
      "functionary_bob/build.f6701b1e.link",
      "functionary_bob/inclavare-containers",
      "final_product/jerry.pub",
      "final_product/inclavare-containers",
      "final_product/.check_done",
      "final_product/clone.3b1a98aa.link",
      "final_product/build.f6701b1e.link",
      "final_product/integrity.link",
      "final_product/root.layout",
    ]

    for path in files_to_delete:
      if os.path.isfile(path):
        os.remove(path)
      elif os.path.isdir(path):
        rmtree(path)

    sys.exit(0)
  if args.no_prompt:
    global NO_PROMPT
    NO_PROMPT = True


  supply_chain()

if __name__ == '__main__':
  main()
