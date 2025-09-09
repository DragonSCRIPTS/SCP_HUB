-- ====================================
-- BASE64 DECODER MODULE
-- Especializado em detectar e decodificar strings Base64
-- ====================================

local Base64DecoderModule = {
    name = "Base64Decoder",
    version = "1.0.0",
    priority = 3,
    description = "Detecta e decodifica strings codificadas em Base64",
    author = "ModuleSystem",
    
    -- Padrões Base64 comuns
    patterns = {
        -- Base64 puro
        '"([A-Za-z0-9+/=]{16,})"',
        "'([A-Za-z0-9+/=]{16,})'",
        -- Base64 com prefixos
        'base64%s*:%s*"([A-Za-z0-9+/=]+)"',
        'data:text/plain;base64,([A-Za-z0-9+/=]+)',
        -- Base64 em arrays
        '{%s*"([A-Za-z0-9+/=]+)"%s*}',
        -- Base64 concatenado
        'string%.char%([^)]*%)',
    },
    
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end
        
        local source = script.Source
        
        -- Verifica se há padrões Base64 no código
        for _, pattern in pairs(Base64DecoderModule.patterns) do
            if source:find(pattern) then
                return true
            end
        end
        
        -- Verifica indicadores de Base64
        local indicators = {
            "base64", "decode", "fromBase64", "b64decode",
            "atob", "btoa", "encoded", "decode64"
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
        
        -- Decodifica strings Base64 encontradas
        for _, pattern in pairs(Base64DecoderModule.patterns) do
            decoded = decoded:gsub(pattern, function(match)
                local decodedString = Base64DecoderModule:decodeBase64(match)
                if decodedString and #decodedString > 0 and decodedString ~= match then
                    decodedCount = decodedCount + 1
                    table.insert(results, {
                        original = match:sub(1, 50) .. "...",
                        decoded = decodedString:sub(1, 100) .. "...",
                        method = "base64"
                    })
                    return '-- [DECODED BASE64]: ' .. decodedString
                end
                return match
            end)
        end
        
        if decodedCount > 0 then
            local header = "-- Base64 Decoder Results: " .. decodedCount .. " strings decoded\n"
            for i, result in pairs(results) do
                header = header .. "-- [" .. i .. "] Original: " .. result.original .. "\n"
                header = header .. "-- [" .. i .. "] Decoded: " .. result.decoded .. "\n"
            end
            header = header .. "-- ================================\n\n"
            
            return header .. decoded, "base64_decoded"
        end
        
        return nil
    end,
    
    -- Função auxiliar para decodificar Base64
    decodeBase64 = function(self, encoded)
        -- Remove espaços e quebras de linha
        encoded = encoded:gsub("%s+", "")
        
        -- Verifica se é Base64 válido
        if #encoded % 4 ~= 0 then return nil end
        if not encoded:match("^[A-Za-z0-9+/]*=*$") then return nil end
        
        local success, result = pcall(function()
            -- Método 1: Usando HttpService (mais confiável)
            local httpService = game:GetService("HttpService")
            return httpService:GetAsync("data:text/plain;base64," .. encoded)
        end)
        
        if success and result then
            return result
        end
        
        -- Método 2: Decodificação manual
        return self:manualBase64Decode(encoded)
    end,
    
    -- Decodificação manual de Base64
    manualBase64Decode = function(self, encoded)
        local chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        local decoded = ""
        
        -- Remove padding
        encoded = encoded:gsub("=", "")
        
        for i = 1, #encoded, 4 do
            local chunk = encoded:sub(i, i + 3)
            local bits = ""
            
            for j = 1, #chunk do
                local char = chunk:sub(j, j)
                local index = chars:find(char)
                if not index then return nil end
                
                local binary = ""
                local num = index - 1
                for k = 5, 0, -1 do
                    binary = binary .. (math.floor(num / (2^k)) % 2)
                end
                bits = bits .. binary
            end
            
            -- Converte bits para caracteres
            for k = 1, #bits, 8 do
                local byte = bits:sub(k, k + 7)
                if #byte == 8 then
                    decoded = decoded .. string.char(tonumber(byte, 2))
                end
            end
        end
        
        return decoded
    end,
    
    detect = function(script)
        if not script or not script.Source then 
            return {obfuscated = false, method = "none", confidence = 0}
        end
        
        local source = script.Source
        local base64Count = 0
        local totalMatches = 0
        
        -- Conta padrões Base64
        for _, pattern in pairs(Base64DecoderModule.patterns) do
            for match in source:gmatch(pattern) do
                totalMatches = totalMatches + 1
                if Base64DecoderModule:isValidBase64(match) then
                    base64Count = base64Count + 1
                end
            end
        end
        
        local confidence = totalMatches > 0 and (base64Count / totalMatches) or 0
        
        return {
            obfuscated = base64Count > 0,
            method = base64Count > 0 and "base64_encoding" or "none",
            confidence = confidence,
            details = {
                base64_strings = base64Count,
                total_matches = totalMatches
            }
        }
    end,
    
    -- Verifica se uma string é Base64 válida
    isValidBase64 = function(self, str)
        if not str or #str < 4 then return false end
        if #str % 4 ~= 0 then return false end
        return str:match("^[A-Za-z0-9+/]*=*$") ~= nil
    end
}

return Base64DecoderModule
