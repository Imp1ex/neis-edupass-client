(function() {
        if (typeof CryptoJS_neis !== 'undefined' && CryptoJS_neis.AES) {
        const orig3 = CryptoJS_neis.AES.encrypt;
        CryptoJS_neis.AES.encrypt = function(m, k, o) {
            console.log("키:", k);
            return orig3.call(this, m, k, o);
        };
    }
    
    console.log("후킹 완료. 로그인을 시도하세요.");
})();