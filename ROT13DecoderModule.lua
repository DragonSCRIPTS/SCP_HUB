-- ====================================
-- ROT13 DECODER MODULE
-- Especializado em descriptografar código protegido por cifra ROT13
-- ====================================

local ROT13DecoderModule = {
    name = "ROT13Decoder",
    version = "1.0.0",
    priority = 6,
    description = "Detecta e descriptografa código protegido por obfuscação ROT13",
    author = "ModuleSystem",

    -- Configurações padrão
    shift = 13, -- Deslocamento padrão do ROT13
    minConfidence = 0.7, -- Limiar de confiança para considerar ROT13

    -- Assinaturas comuns de código com ROT13
    rot13Signatures = {
        -- Padrões de texto rotacionado
        "[a-mA-M][n-zN-Z]", -- Transições típicas de ROT13
        "[n-zN-Z][a-mA-M]", -- Transições inversas
        "string%.gsub%s*%(%s*[^\)]+%s*,%s*[^\)]+%s*,%s*[^\)]+%s*%)", -- Substituições genéricas
        "%w+%s*rot%s*13", -- Referências explícitas a ROT13

        -- Padrões de strings potencialmente rotacionadas
        "[a-zA-Z]{5,}%s+[^%w%s]", -- Sequências longas de letras
        "local%s+%w+%s*=%s*['\"][a-zA-Z]+['\"]", -- Strings atribuídas
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #ROT13DecoderModule.rot13Signatures

        for _, signature in pairs(ROT13DecoderModule.rot13Signatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        return confidence >= ROT13DecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated = ROT13DecoderModule:decodeROT13(source)
        if not deobfuscated or deobfuscated == source then
            return nil
        end

        local header = "-- ROT13 Deobfuscator Results\n"
        header = header .. "-- Shift applied: 13 positions\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "rot13_decoded"
    end,

    -- Descriptografa usando ROT13
    decodeROT13 = function(self, source)
        return source:gsub("[a-zA-Z]", function(c)
            local base = c:match("[a-z]") and 97 or 65 -- 'a' = 97, 'A' = 65
            local charCode = string.byte(c) - base
            charCode = (charCode + self.shift) % 26
            return string.char(base + charCode)
        end)
    end,

    -- Detecta se o código foi obfuscação por ROT13
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #ROT13DecoderModule.rot13Signatures

        for _, signature in pairs(ROT13DecoderModule.rot13Signatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isROT13 = confidence >= ROT13DecoderModule.minConfidence

        return {
            obfuscated = isROT13,
            method = isROT13 and "rot13_obfuscation" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 5 and "HIGH" or "LOW"
            }
        }
    end,
}

return ROT13DecoderModule
