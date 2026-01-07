// Quick Scan Demo File
// This file contains obvious earlystage risky code

function normalStuff() {
  console.log("Hello world");
}

eval("console.log('Quick scan should detect this')");

// some filler
for (let i = 0; i < 1000; i++) {
  console.log(i);
}
