-- ====================================
-- AES DECODER MODULE
-- Especializado em descriptografar código protegido por criptografia AES
-- ====================================

local AESDecoderModule = {
    name = "AESDecoder",
    version = "1.0.0",
    priority = 9,
    description = "Detecta e descriptografa código protegido por criptografia AES",
    author = "ModuleSystem",

    -- Configurações padrão
    minConfidence = 0.8, -- Limiar de confiança para considerar AES
    defaultKey = "defaultaeskey123", -- Chave padrão (simulada)

    -- Assinaturas comuns de código criptografado com AES
    aesSignatures = {
        -- Padrões de chamadas a funções criptográficas
        "aes%.encrypt", -- Referências a AES
        "require%s*['\"]crypto['\"]", -- Importação de bibliotecas criptográficas
        "string%.sub%s*%(%s*[^\)]+%s*,%s*%d+%s*,%s*%d+%s*%)", -- Extração de blocos

        -- Padrões de dados criptografados
        "[%x]{16,}", -- Blocos de 16 bytes (tamanho típico de AES)
        "local%s+%w+%s*=%s*['\"][%x]+['\"]", -- Strings hexadecimais longas
        "bit32%.bxor%s*%(%s*[^\)]+%s*,%s*[^\)]+%s*%)", -- Operações bitwise associadas
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #AESDecoderModule.aesSignatures

        for _, signature in pairs(AESDecoderModule.aesSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        return confidence >= AESDecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated = AESDecoderModule:decodeAES(source)
        if not deobfuscated then
            return nil
        end

        local header = "-- AES Deobfuscator Results\n"
        header = header .. "-- Key used: " .. AESDecoderModule.defaultKey .. " (simulated)\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "aes_decoded"
    end,

    -- Descriptografa usando AES (simulação básica)
    decodeAES = function(self, source)
        -- Nota: Esta é uma simulação. Para funcionalidade real, use uma biblioteca como lua-crypto.
        if source:find("[%x]{16,}") then
            -- Simula a descriptografia convertendo hex para texto legível (placeholder)
            return "-- Decrypted AES data (use lua-crypto for real decryption)\n" .. source:gsub("[%x]+", function(hex)
                return "DECRYPTED_" .. hex:sub(1, 8) -- Substitui por placeholder
            end)
        end
        return nil
    end,

    -- Detecta se o código foi criptografado com AES
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #AESDecoderModule.aesSignatures

        for _, signature in pairs(AESDecoderModule.aesSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isAES = confidence >= AESDecoderModule.minConfidence

        return {
            obfuscated = isAES,
            method = isAES and "aes_encryption" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 6 and "HIGH" or "LOW"
            }
        }
    end,
}

return AESDecoderModule
