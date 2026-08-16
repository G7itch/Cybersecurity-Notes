# JavaScript Deobfuscation Module

## <u>*Introduction*</u>

Obfuscation is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view. This is usually achieved by using an obfuscation tool which takes the original code in as input. There are many reasons why developers may consider obfuscating their code - a common reason is to prevent it being reused or copied without permission, another could be to provide an extra layer of security.

Obfuscation is usually not done manually as there are many tools for various languages that can automate the process. A common way of reducing the readability of a snippet of JavaScript whilst keeping it functional is through minimisation. There are lots of tools to help minify JavaScript such as <https://javascript-minifier.com/>. Usually minified JavaScript is saved with the extension .min.js. We can use <http://beautifytools.com/javascript-obfuscator.php> to obfuscate our code. This type of obfuscation is known as packing. Note that packers leave the main strings of the code written in cleartext which can give away the functions of the code.

## <u>*More Advanced Obfuscation*</u>

We can use the online tool <https://obfuscator.io/> and change the String array encoding to base64. The code should now bear no resemblance to the original code however we will notice a performance decrease.

## <u>*Deobfuscation*</u>

The first thing we can attempt to get the code human readable is to run it through a Beautifier tool. The most basic way of doing this is through the browser dev tools. We can find many good tools to try and deobfuscate JavaScript online and turn it into something understandable. One such tool is <https://matthewfl.com/unPacker.html>. Another technique we can use for packed code is to find the return statement and print it instead of executing it. However this will be more complicated if the code was obfuscated using a custom tool.

Code can be encoded using several different methods and we will often encounter encoded text blocks, we can decode these using online tools or in the terminal.

### Base64

```bash
echo plaintext | base64
```

```bash
echo encodedtext | base64 -d
```

### Hex

```bash
echo plaintext | xxd -p
```

```bash
echo hexencoded | xxd -p -r
```

### Caesar

```bash
echo plaintext | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```bash
echo encodedtext | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

If you need help identifying what type of encoding is being used we can look at online tools. For help decoding we can use cyberchef. 
