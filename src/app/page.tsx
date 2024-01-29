'use client'

import Image from 'next/image'
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512'
import { sha1 } from '@noble/hashes/sha1';
import { scrypt, scryptAsync } from '@noble/hashes/scrypt';
import { argon2id } from '@noble/hashes/argon2';
import { scryptSync } from 'node:crypto';
import { useState } from 'react';

export default function Home() {

    const [device, setDevice] = useState("laptop");

    function runNobleScrypt() : void {
        // Each of the below scrypt hashes provides roughly equivalent security, as provided by OWASP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
        console.log('Testing OWASP recommended params for noble-hashes scrypt');
        var start = window.performance.now();
        var scr = scrypt('myPassword', '1DG89RTCF5BN3E7Y', { N: 2 ** 17, r: 8, p: 1, dkLen: 32 }); // Work factor 2^17
        var end = window.performance.now();
        console.log('Noble scrypt {N: 2**17 , r: 8, p: 1} => ' + (end - start));

        start = window.performance.now();
        scr = scrypt('myPassword', '1DG89RTCF5BN3E7Y', { N: 2 ** 16, r: 8, p: 2, dkLen: 32 }); // Work factor 2^16 + 2 degrees parallelism
        end = window.performance.now();
        console.log('Noble scrypt {N: 2**16 , r: 8, p: 2} => ' + (end - start));

        start = window.performance.now();
        scr = scrypt('myPassword', '1DG89RTCF5BN3E7Y', { N: 2 ** 15, r: 8, p: 3, dkLen: 32 }); // Work factor 2^15
        end = window.performance.now();
        console.log('Noble scrypt {N: 2**15 , r: 8, p: 3} => ' + (end - start));

        start = window.performance.now();
        scr = scrypt('myPassword', '1DG89RTCF5BN3E7Y', { N: 2 ** 14, r: 8, p: 5, dkLen: 32 }); // Work factor 2^14
        end = window.performance.now();
        console.log('Noble scrypt {N: 2**14 , r: 8, p: 5} => ' + (end - start));

        start = window.performance.now();
        scr = scrypt('myPassword', '1DG89RTCF5BN3E7Y', { N: 2 ** 13, r: 8, p: 10, dkLen: 32 }); // Work factor 2^13
        end = window.performance.now();
        console.log('Noble scrypt {N: 2**13 , r: 8, p: 10} => ' + (end - start));
    }


    function runNodeScrypt() : void {
       // Each of the below scrypt hashes provides roughly equivalent security, as provided by OWASP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
       console.log('Testing OWASP recommended params for node-crypto scrypt');
       var start = window.performance.now();
       var scr = scryptSync('myPassword', '1DG89RTCF5BN3E7Y', 32, { N: 2 ** 17, r: 8, p: 1 }); // Work factor 2^17
       var end = window.performance.now();
       console.log('Noble scrypt {N: 2**17 , r: 8, p: 1} => ' + (end - start));

       start = window.performance.now();
       scr = scryptSync('myPassword', '1DG89RTCF5BN3E7Y', 32, { N: 2 ** 16, r: 8, p: 2 }); // Work factor 2^16 + 2 degrees parallelism
       end = window.performance.now();
       console.log('Noble scrypt {N: 2**16 , r: 8, p: 2} => ' + (end - start));

       start = window.performance.now();
       scr = scryptSync('myPassword', '1DG89RTCF5BN3E7Y', 32, { N: 2 ** 15, r: 8, p: 3 }); // Work factor 2^15 + 3 degrees parallelism
       end = window.performance.now();
       console.log('Noble scrypt {N: 2**15 , r: 8, p: 3} => ' + (end - start));

       start = window.performance.now();
       scr = scryptSync('myPassword', '1DG89RTCF5BN3E7Y', 32, { N: 2 ** 14, r: 8, p: 5 }); // Work factor 2^14 + 5 degrees parallelism
       end = window.performance.now();
       console.log('Noble scrypt {N: 2**14 , r: 8, p: 5} => ' + (end - start));

       start = window.performance.now();
       scr = scryptSync('myPassword', '1DG89RTCF5BN3E7Y', 32, { N: 2 ** 13, r: 8, p: 10 }); // Work factor 2^13 + 10 degrees parallelism
       end = window.performance.now();
       console.log('Noble scrypt {N: 2**13 , r: 8, p: 10} => ' + (end - start));
    }

    function runNoblePbk() : void {
        // Read here about potential weaknesses in Pbkdf2 https://en.wikipedia.org/wiki/PBKDF2#Alternatives_to_PBKDF2
        // Each of the following are roughly equivalent in terms of security, as provided by OWASP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        var start = window.performance.now();
        var dk = pbkdf2(sha256, 'myPassword', '1DG89RTCF5BN3E7Y', { c: 600000, dkLen: 32 }); // OWASP recommended minimum # of iterations
        var end = window.performance.now();
        console.log('Noble pbkdf2 with sha256 + 600,000 iterations time elapsed: ' + (end - start));

        start = window.performance.now();
        dk = pbkdf2(sha512, 'myPassword', '1DG89RTCF5BN3E7Y', { c: 210000, dkLen: 32 });
        end = window.performance.now();
        console.log('Noble pbkdf2 with sha512 + 210,000 iterations time elapsed: ' + (end - start));

        start = window.performance.now();
        dk = pbkdf2(sha1, 'myPassword', '1DG89RTCF5BN3E7Y', { c: 1300000, dkLen: 32 });
        end = window.performance.now();
        console.log('Noble pbkdf2 with sha1 + 1,300,000 iterations time elapsed: ' + (end - start));

    }

    function runNobleArgon2id() : string[] {
        // Recommended params by OWASP + 16 Byte salt for a standard string password
        // KEY NOTES: 
        // 1. Each of the below are recommended param combinations by OWASP with roughly equivalent cryptographic strengths https://en.wikipedia.org/wiki/Argon2#Recommended_minimum_parameters
        // 2. Greater memory means more secure, more iterations means more secure

        const output : string[] = [];

        console.log("Testing OWASP recommended params for noble-hashes experimental argon2id");
        var start = window.performance.now();
        var result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 2, m: 19923, p: 1 }); // Roughly 19 MiB of memory
        var end = window.performance.now();
        console.log('Noble Argon2id 19 MiB memory + 2 iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 3, m: 12583, p: 1 }); // Roughly 12 MiB of memory + 3 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 12 MiB memory + 3 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 4, m: 9437, p: 1 }); // Roughly 9 MiB of memory + 4 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 9 MiB memory + 4 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 5, m: 7340, p: 1 }); // Roughly 7 MiB of memory + 5 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 7 MiB memory + 5 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

        return output;
    }

    function runNobleArgon2i() : void {
        // Recommended params by OWASP + 16 Byte salt for a standard string password
        // KEY NOTES: 
        // 1. Each of the below are recommended param combinations by OWASP with roughly equivalent cryptographic strengths https://en.wikipedia.org/wiki/Argon2#Recommended_minimum_parameters
        // 2. Greater memory means more secure, more iterations means more secure

        console.log("Testing OWASP recommended params for noble-hashes experimental argon2id");
        var start = window.performance.now();
        var result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 2, m: 19923, p: 1 }); // Roughly 19 MiB of memory
        var end = window.performance.now();
        console.log('Noble Argon2id 19 MiB memory + 2 iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 3, m: 12583, p: 1 }); // Roughly 12 MiB of memory + 3 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 12 MiB memory + 3 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 4, m: 9437, p: 1 }); // Roughly 9 MiB of memory + 4 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 9 MiB memory + 4 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

        start = window.performance.now();
        result = argon2id('myPassword', '1DG89RTCF5BN3E7Y', { t: 5, m: 7340, p: 1 }); // Roughly 7 MiB of memory + 5 Iterations
        end = window.performance.now();
        console.log('Noble Argon2id 7 MiB memory + 5 Iterations + 1 degree parallelism elapsed time: ' + (end - start));

    }

    function runWebcryptoPbk() : void {
        
    }

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <div className="z-10 max-w-5xl w-full items-center justify-between font-mono text-sm lg:flex">
        <button id="noble-hash-scrypt" className="test-button" onClick={runNobleScrypt}>Run noble's scrypt tests</button>
        <button id="noble-hash-pbkdf2" className="test-button" onClick={runNoblePbk}>Run noble's pbkdf2 tests</button>
        <button id="noble-hash-argon2id" className="test-button" onClick={runNobleArgon2id} >Run noble's argon2id tests</button>
        <button id="noble-hash-argon2i" className="test-button">Run noble"s argon2i tests</button>
        <button id="webcrypto-pbkdf2" className="test-button">Run webcrypto's pdkdf2 tests</button>
        <button id="node-scrypt" className="test-button" onClick={runNodeScrypt}>Run node's scrypt tests</button>
      </div>
      <div>
        <button id="device" onClick={() => (device == "laptop") ? setDevice("mobile") : setDevice("laptop")}>
            <h1>Device:</h1>
            <h3>{device}</h3>
        </button>
      </div>
    </main>
  )
}
