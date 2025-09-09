-- ====================================
-- SUBSTITUTION DECODER MODULE
-- Especializado em descriptografar código protegido por cifra de substituição
-- ====================================

local SubstitutionDecoderModule = {
    name = "SubstitutionDecoder",
    version = "1.0.0",
    priority = 5,
    description = "Detecta e descriptografa código protegido por obfuscação de substituição de caracteres",
    author = "ModuleSystem",

    -- Configurações padrão
    defaultMap = { -- Mapeamento simples (exemplo: A -> Z, B -> Y, etc.)
        ["a"] = "z", ["b"] = "y", ["c"] = "x", ["d"] = "w", ["e"] = "v",
        ["f"] = "u", ["g"] = "t", ["h"] = "s", ["i"] = "r", ["j"] = "q",
        ["k"] = "p", ["l"] = "o", ["m"] = "n", ["n"] = "m", ["o"] = "l",
        ["p"] = "k", ["q"] = "j", ["r"] = "i", ["s"] = "h", ["t"] = "g",
        ["u"] = "f", ["v"] = "e", ["w"] = "d", ["x"] = "c", ["y"] = "b",
        ["z"] = "a",
        ["A"] = "Z", ["B"] = "Y", ["C"] = "X", ["D"] = "W", ["E"] = "V",
        ["F"] = "U", ["G"] = "T", ["H"] = "S", ["I"] = "R", ["J"] = "Q",
        ["K"] = "P", ["L"] = "O", ["M"] = "N", ["N"] = "M", ["O"] = "L",
        ["P"] = "K", ["Q"] = "J", ["R"] = "I", ["S"] = "H", ["T"] = "G",
        ["U"] = "F", ["V"] = "E", ["W"] = "D", ["X"] = "C", ["Y"] = "B",
        ["Z"] = "A"
    },
    minConfidence = 0.65, -- Limiar de confiança para considerar substituição

    -- Assinaturas comuns de código com cifra de substituição
    substitutionSignatures = {
        -- Padrões de strings alteradas
        "[a-zA-Z]%s*=%s*[a-zA-Z]", -- Atribuições de caracteres
        "string%.gsub%s*%(%s*[^\)]+%s*,%s*['\"][a-zA-Z]['\"]%s*,%s*['\"][a-zA-Z]['\"]%s*%)", -- Substituições visíveis
        "[a-zA-Z]{10,}%s+[^%w%s]", -- Sequências longas de letras seguidas por símbolos

        -- Padrões de texto potencialmente ofuscado
        "%w+%s*:[%s*%w+]", -- Mapeamentos em tabelas
        "local%s+%w+%s*=%s*string%.char%s*%(%d+%s*%)", -- Conversões de caracteres
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #SubstitutionDecoderModule.substitutionSignatures

        for _, signature in pairs(SubstitutionDecoderModule.substitutionSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        return confidence >= SubstitutionDecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated = SubstitutionDecoderModule:decodeSubstitution(source)
        if not deobfuscated or deobfuscated == source then
            return nil
        end

        local header = "-- Substitution Deobfuscator Results\n"
        header = header .. "-- Method: Character substitution\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "substitution_decoded"
    end,

    -- Descriptografa usando substituição de caracteres
    decodeSubstitution = function(self, source)
        return source:gsub(".", function(c)
            return self.defaultMap[c] or c
        end)
    end,

    -- Detecta se o código foi obfuscação por substituição
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #SubstitutionDecoderModule.substitutionSignatures

        for _, signature in pairs(SubstitutionDecoderModule.substitutionSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isSubstitution = confidence >= SubstitutionDecoderModule.minConfidence

        return {
            obfuscated = isSubstitution,
            method = isSubstitution and "substitution_obfuscation" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 6 and "HIGH" or "LOW"
            }
        }
    end,
}

return SubstitutionDecoderModule
