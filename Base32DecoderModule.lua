-- ====================================
-- BASE32 DECODER MODULE
-- Especializado em descriptografar código protegido por codificação Base32
-- ====================================

local Base32DecoderModule = {
    name = "Base32Decoder",
    version = "1.0.0",
    priority = 8,
    description = "Detecta e descriptografa código protegido por codificação Base32",
    author = "ModuleSystem",

    -- Configurações padrão
    minConfidence = 0.7, -- Limiar de confiança para considerar Base32
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", -- Alfabeto Base32 padrão

    -- Assinaturas comuns de código codificado em Base32
    base32Signatures = {
        -- Padrões de strings Base32
        "[A-Z2-7]{8,}(==?)?", -- Sequências de 8 ou mais caracteres Base32, possivelmente terminadas com '='
        "string%.gsub%s*%(%s*[^\)]+%s*,%s*['\"][A-Z2-7]+['\"]%s*%)", -- Substituições Base32
        "base32%.decode", -- Referências a decodificação Base32

        -- Padrões de dados codificados
        "[A-Z2-7]%s*:%s*[A-Z2-7]", -- Mapeamentos ou pares Base32
        "local%s+%w+%s*=%s*['\"][A-Z2-7]+['\"]", -- Strings Base32 atribuídas
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #Base32DecoderModule.base32Signatures

        for _, signature in pairs(Base32DecoderModule.base32Signatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        return confidence >= Base32DecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated = Base32DecoderModule:decodeBase32(source)
        if not deobfuscated then
            return nil
        end

        local header = "-- Base32 Deobfuscator Results\n"
        header = header .. "-- Method: Base32 decoding\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "base32_decoded"
    end,

    -- Decodifica usando Base32 (implementação simplificada)
    decodeBase32 = function(self, source)
        -- Função auxiliar para converter um grupo de 8 caracteres Base32 em 5 bytes
        local function decodeGroup(group)
            if #group == 0 then return nil end
            local bits = 0
            local bitLength = 0

            for i = 1, #group do
                local pos = self.alphabet:find(group:sub(i, i))
                if not pos then return nil end
                bits = bits * 32 + (pos - 1)
                bitLength = bitLength + 5
            end

            local bytes = {}
            for i = 1, math.floor((bitLength + 7) / 8) do
                local byte = bit32.band(bit32.rshift(bits, (bitLength - 8 * i)), 0xFF)
                if byte > 0 then
                    table.insert(bytes, 1, string.char(byte))
                end
            end
            return table.concat(bytes)
        end

        -- Remove padding e processa em grupos de 8
        source = source:gsub("%s+", ""):gsub("=*$", "")
        local result = ""
        for i = 1, #source - 7, 8 do
            local group = source:sub(i, i + 7)
            local decoded = decodeGroup(group)
            if decoded then
                result = result .. decoded
            else
                return nil
            end
        end

        return result ~= "" and result or nil
    end,

    -- Detecta se o código foi codificado em Base32
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #Base32DecoderModule.base32Signatures

        for _, signature in pairs(Base32DecoderModule.base32Signatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isBase32 = confidence >= Base32DecoderModule.minConfidence

        return {
            obfuscated = isBase32,
            method = isBase32 and "base32_encoding" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 5 and "HIGH" or "LOW"
            }
        }
    end,
}

return Base32DecoderModule
