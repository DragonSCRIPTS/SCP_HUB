-- ====================================
-- HEXADECIMAL DECODER MODULE
-- Especializado em detectar e decodificar strings Hexadecimais
-- ====================================

local HexDecoderModule = {
    name = "HexDecoder",
    version = "1.0.0",
    priority = 4,
    description = "Detecta e decodifica strings codificadas em Hexadecimal",
    author = "ModuleSystem",
    
    -- Padrões Hexadecimais comuns
    patterns = {
        -- Hex puro entre aspas
        '"([0-9A-Fa-f]{8,})"',
        "'([0-9A-Fa-f]{8,})'",
        -- Hex com prefixos
        '0x([0-9A-Fa-f]+)',
        'hex%s*:%s*"([0-9A-Fa-f]+)"',
        -- Hex em arrays
        '{%s*"([0-9A-Fa-f]+)"%s*}',
        -- Hex separado por espaços
        '"([0-9A-Fa-f%s]+)"',
        -- Hex com separadores
        '"([0-9A-Fa-f%-]+)"',
        '"([0-9A-Fa-f_]+)"',
    },
    
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end
        
        local source = script.Source
        
        -- Verifica padrões Hex no código
        for _, pattern in pairs(HexDecoderModule.patterns) do
            if source:find(pattern) then
                return true
            end
        end
        
        -- Verifica indicadores de Hexadecimal
        local indicators = {
            "hex", "0x", "fromHex", "hexdecode", "tohex",
            "hexstr", "hex2str", "unhex", "hexadecimal"
        }
        
        for _, indicator in pairs(indicators) do
            if source:lower():find(indicator:lower()) then
                return true
            end
        end
        
        return false
    end,
    
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end
        
        local decoded = source
        local decodedCount = 0
        local results = {}
        
        -- Decodifica strings Hex encontradas
        for _, pattern in pairs(HexDecoderModule.patterns) do
            decoded = decoded:gsub(pattern, function(match)
                local decodedString = HexDecoderModule:decodeHex(match)
                if decodedString and #decodedString > 0 and decodedString ~= match then
                    decodedCount = decodedCount + 1
                    table.insert(results, {
                        original = match:sub(1, 50) .. "...",
                        decoded = decodedString:sub(1, 100) .. "...",
                        method = "hexadecimal"
                    })
                    return '-- [DECODED HEX]: ' .. decodedString
                end
                return match
            end)
        end
        
        if decodedCount > 0 then
            local header = "-- Hexadecimal Decoder Results: " .. decodedCount .. " strings decoded\n"
            for i, result in pairs(results) do
                header = header .. "-- [" .. i .. "] Original: " .. result.original .. "\n"
                header = header .. "-- [" .. i .. "] Decoded: " .. result.decoded .. "\n"
            end
            header = header .. "-- ================================\n\n"
            
            return header .. decoded, "hex_decoded"
        end
        
        return nil
    end,
    
    -- Função principal para decodificar Hexadecimal
    decodeHex = function(self, encoded)
        if not encoded or #encoded < 2 then return nil end
        
        -- Remove prefixos comuns
        encoded = encoded:gsub("^0x", "")
        
        -- Remove separadores
        encoded = encoded:gsub("[%s%-_]", "")
        
        -- Verifica se é hex válido
        if not self:isValidHex(encoded) then return nil end
        
        -- Garante que tem número par de caracteres
        if #encoded % 2 ~= 0 then
            encoded = "0" .. encoded
        end
        
        local decoded = ""
        local success, result = pcall(function()
            for i = 1, #encoded, 2 do
                local hexByte = encoded:sub(i, i + 1)
                local byteValue = tonumber(hexByte, 16)
                if byteValue then
                    decoded = decoded .. string.char(byteValue)
                end
            end
            return decoded
        end)
        
        if success and #result > 0 then
            -- Verifica se o resultado contém caracteres imprimíveis
            if self:isPrintable(result) then
                return result
            end
        end
        
        return nil
    end,
    
    -- Decodificação com diferentes formatos
    decodeHexAdvanced = function(self, encoded)
        local formats = {
            -- Formato padrão
            function(s) return s:gsub("[%s%-_]", "") end,
            -- Formato com espaços a cada 2 caracteres
            function(s) return s:gsub("%s", "") end,
            -- Formato com separadores
            function(s) return s:gsub("[%-_]", "") end,
            -- Formato reverso (little endian)
            function(s) 
                s = s:gsub("[%s%-_]", "")
                local reversed = ""
                for i = #s, 1, -2 do
                    reversed = reversed .. s:sub(i-1, i)
                end
                return reversed
            end
        }
        
        for _, formatter in pairs(formats) do
            local formatted = formatter(encoded)
            local result = self:decodeHex(formatted)
            if result and self:isPrintable(result) then
                return result
            end
        end
        
        return nil
    end,
    
    detect = function(script)
        if not script or not script.Source then 
            return {obfuscated = false, method = "none", confidence = 0}
        end
        
        local source = script.Source
        local hexCount = 0
        local totalMatches = 0
        
        -- Conta padrões Hex
        for _, pattern in pairs(HexDecoderModule.patterns) do
            for match in source:gmatch(pattern) do
                totalMatches = totalMatches + 1
                if HexDecoderModule:isValidHex(match) then
                    hexCount = hexCount + 1
                end
            end
        end
        
        local confidence = totalMatches > 0 and (hexCount / totalMatches) or 0
        
        return {
            obfuscated = hexCount > 0,
            method = hexCount > 0 and "hexadecimal_encoding" or "none",
            confidence = confidence,
            details = {
                hex_strings = hexCount,
                total_matches = totalMatches
            }
        }
    end,
    
    -- Verifica se uma string é Hex válida
    isValidHex = function(self, str)
        if not str or #str < 2 then return false end
        -- Remove prefixos e separadores
        str = str:gsub("^0x", ""):gsub("[%s%-_]", "")
        return str:match("^[0-9A-Fa-f]*$") ~= nil
    end,
    
    -- Verifica se o resultado contém caracteres imprimíveis
    isPrintable = function(self, str)
        if not str or #str == 0 then return false end
        
        local printableCount = 0
        for i = 1, #str do
            local byte = str:byte(i)
            -- Caracteres imprimíveis ASCII (32-126) + alguns especiais
            if (byte >= 32 and byte <= 126) or byte == 9 or byte == 10 or byte == 13 then
                printableCount = printableCount + 1
            end
        end
        
        -- Pelo menos 70% dos caracteres devem ser imprimíveis
        return (printableCount / #str) >= 0.7
    end,
    
    -- Função utilitária para converter string para hex (encoding)
    encodeHex = function(self, str)
        local hex = ""
        for i = 1, #str do
            hex = hex .. string.format("%02X", str:byte(i))
        end
        return hex
    end
}

return HexDecoderModule
