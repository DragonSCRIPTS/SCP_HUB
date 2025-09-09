-- ====================================
-- BITSHIFT DECODER MODULE
-- Especializado em descriptografar código protegido por deslocamento de bits
-- ====================================

local BitShiftDecoderModule = {
    name = "BitShiftDecoder",
    version = "1.0.0",
    priority = 4,
    description = "Detecta e descriptografa código protegido por obfuscação de deslocamento de bits",
    author = "ModuleSystem",

    -- Configurações padrão
    defaultShift = 2, -- Deslocamento padrão (bits)
    minConfidence = 0.6, -- Limiar de confiança para considerar bit shifting

    -- Assinaturas comuns de código com deslocamento de bits
    bitShiftSignatures = {
        -- Padrões de operações bitwise
        "bit32%.lshift", -- Deslocamento à esquerda
        "bit32%.rshift", -- Deslocamento à direita
        "%s<<%s", -- Operador de deslocamento à esquerda
        "%s>>%s", -- Operador de deslocamento à direita
        "bit32%.band%s*%(%s*[%w_]+%s*,%s*%d+%s*%)", -- AND bitwise com constantes

        -- Padrões de resultados típicos
        "[%z-\xff][%z-\xff]%s*<<%s*%d+", -- Deslocamento em sequências
    },

    -- Verifica se o script pode ser tratado por este módulo
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #BitShiftDecoderModule.bitShiftSignatures

        -- Conta assinaturas encontradas
        for _, signature in pairs(BitShiftDecoderModule.bitShiftSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        -- Confiança baseada na proporção de assinaturas
        local confidence = signatureCount / totalSignatures
        return confidence >= BitShiftDecoderModule.minConfidence
    end,

    -- Extrai e descriptografa o código
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end

        local deobfuscated, shiftUsed = BitShiftDecoderModule:decodeBitShift(source, BitShiftDecoderModule.defaultShift)
        if not deobfuscated then
            return nil
        end

        local header = "-- BitShift Deobfuscator Results\n"
        header = header .. "-- Shift applied: " .. shiftUsed .. " bits\n"
        header = header .. "-- ================================\n\n"

        return header .. deobfuscated, "bitshift_decoded"
    end,

    -- Descriptografa usando deslocamento de bits
    decodeBitShift = function(self, source, shift)
        local decoded = {}
        for i = 1, #source do
            local byte = string.byte(source, i)
            -- Aplica deslocamento à direita (inverso de lshift) para descriptografar
            local deobfuscatedByte = bit32.rshift(byte, shift)
            decoded[i] = string.char(deobfuscatedByte)
        end

        return table.concat(decoded), shift
    end,

    -- Detecta se o código foi obfuscação por deslocamento de bits
    detect = function(script)
        if not script or not script.Source then
            return {obfuscated = false, method = "none", confidence = 0}
        end

        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #BitShiftDecoderModule.bitShiftSignatures

        -- Conta assinaturas
        for _, signature in pairs(BitShiftDecoderModule.bitShiftSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end

        local confidence = signatureCount / totalSignatures
        local isBitShift = confidence >= BitShiftDecoderModule.minConfidence

        return {
            obfuscated = isBitShift,
            method = isBitShift and "bitshift_obfuscation" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                obfuscation_level = signatureCount > 4 and "HIGH" or "LOW"
            }
        }
    end,
}

return BitShiftDecoderModule
