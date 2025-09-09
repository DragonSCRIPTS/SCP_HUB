-- ====================================
-- XOR DECODER MODULE
-- Especializado em descriptografar código protegido por XOR com chave fixa
-- ====================================

local XORDecoderModule = {
    name = "XORDecoder",
    version = "1.0.0",
    priority = 3,
    description = "Detecta e descriptografa código protegido por obfuscação XOR",
    author = "ModuleSystem",

    -- Configurações padrão
    defaultKey = "secretkey", -- Chave padrão para tentativa inicial
    minConfidence = 0.7, -- Limiar de confiança para considerar XOR

    -- Assinaturas comuns de código XOR (padrões binários ou repetições)
    xorSignatures = {
        -- Padrões de bytes repetidos ou deslocados
        "[%z-\xff][%z-\xff]%1", -- Dois bytes iguais consecutivos
        "[\128-\255][\128-\255]", -- Bytes altos (pode indicar XOR)
        "string%.byte%s*%(%s*[^\)]+%s*%)%s*~=", -- Operações bitwise

        -- Strings que podem indicar uso de XOR
        "xor%s*[=~]", -- Uso explícito de XOR
        "bit32%.bxor", -- Função Lua para XOR
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #XORDecoderModule.xorSignatures

        -- Conta assinaturas encontradas
        for _, signature in pairs(XORDecoderModule.xorSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        -- Confiança baseada na proporção de assinaturas
        local confidence = signatureCount / totalSignatures
        return confidence >= XORDecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated, keyUsed = XORDecoderModule:decodeXOR(source, XORDecoderModule.defaultKey)
        if not deobfuscated then
            return nil
        end

        local header = "-- XOR Deobfuscator Results\n"
        header = header .. "-- Decryption key: " .. keyUsed .. "\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "xor_decoded"
    end,

    -- Descriptografa usando XOR com uma chave
    decodeXOR = function(self, source, key)
        local keyLen = #key
        if keyLen == 0 then return nil, nil end

        local decoded = {}
        for i = 1, #source do
            local byte = string.byte(source, i)
            local keyByte = string.byte(key, (i - 1) % keyLen + 1)
            decoded[i] = string.char(bit32.bxor(byte, keyByte))
        end

        return table.concat(decoded), key
    end,

    -- Detecta se o código foi obfuscação por XOR
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #XORDecoderModule.xorSignatures

        -- Conta assinaturas
        for _, signature in pairs(XORDecoderModule.xorSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isXOR = confidence >= XORDecoderModule.minConfidence

        return {
            obfuscated = isXOR,
            method = isXOR and "xor_obfuscation" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 5 and "HIGH" or "LOW"
            }
        }
    end,
}

return XORDecoderModule
