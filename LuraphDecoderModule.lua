-- ====================================
-- LURAPH DECODER MODULE
-- Especializado em detectar e desobfuscar código protegido pelo Luraph
-- ====================================

local LuraphDecoderModule = {
    name = "LuraphDecoder",
    version = "1.2.0",
    priority = 2,
    description = "Detecta e desobfusca código protegido pelo obfuscador Luraph",
    author = "ModuleSystem",
    
    -- Identificadores específicos do Luraph
    luraphSignatures = {
        -- Variáveis características
        "upvr", "upvw", "_upvr", "_upvw", "tbl_upvr",
        "arg%d+_upvr", "var%d+_upvw", "pairs_result%d+",
        "upval_%d+", "closure_%d+", "func_%d+_upvr",
        
        -- Padrões de função
        "function%s+upvr_%d+", "function%s+upvw_%d+",
        "local%s+upvr", "local%s+upvw",
        
        -- Estruturas de controle ofuscadas
        "if%s+upvr", "while%s+upvr", "for%s+upvr",
        "repeat%s+upvr", "until%s+upvr",
        
        -- Operações matemáticas ofuscadas
        "upvr%s*%+%s*upvr", "upvr%s*%-%s*upvr",
        "upvr%s*%*%s*upvr", "upvr%s*/%s*upvr",
        
        -- Arrays e tables ofuscados
        "tbl_upvr%[", "%[upvr_%d+%]", "{%s*upvr",
    },
    
    -- Padrões de string ofuscada do Luraph
    stringPatterns = {
        -- Strings codificadas
        'string%.char%s*%(%s*(%d+[%d%s,]*%d+)%s*%)',
        'string%.byte%s*%(%s*"([^"]*)"[^)]*%)',
        -- Tables de bytes
        '{%s*(%d+[%d%s,]*%d+)%s*}',
        -- Concatenação ofuscada
        '%.%.%s*string%.char%s*%(',
    },
    
    canHandle = function(script, metadata)
        if not script or not script.Source then return false end
        
        local source = script.Source
        local signatureCount = 0
        
        -- Verifica assinaturas específicas do Luraph
        for _, signature in pairs(LuraphDecoderModule.luraphSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end
        
        -- Se encontrar pelo menos 3 assinaturas, é provavelmente Luraph
        return signatureCount >= 3
    end,
    
    extract = function(script, options)
        local source = script.Source
        if not source then return nil end
        
        local deobfuscated = source
        local changes = 0
        
        -- Etapa 1: Decodificar strings
        deobfuscated, changes = LuraphDecoderModule:decodeStrings(deobfuscated)
        
        -- Etapa 2: Simplificar variáveis
        deobfuscated = LuraphDecoderModule:simplifyVariables(deobfuscated)
        
        -- Etapa 3: Limpar estruturas de controle
        deobfuscated = LuraphDecoderModule:cleanControlStructures(deobfuscated)
        
        -- Etapa 4: Reconstruir funções
        deobfuscated = LuraphDecoderModule:reconstructFunctions(deobfuscated)
        
        if changes > 0 then
            local header = "-- Luraph Deobfuscator Results\n"
            header = header .. "-- Decoded strings: " .. changes .. "\n"
            header = header .. "-- Original obfuscation level: HIGH\n"
            header = header .. "-- ================================\n\n"
            
            return header .. deobfuscated, "luraph_decoded"
        end
        
        return nil
    end,
    
    -- Decodifica strings ofuscadas
    decodeStrings = function(self, source)
        local decoded = source
        local changeCount = 0
        
        -- Decodifica string.char(números...)
        decoded = decoded:gsub('string%.char%s*%(%s*([%d%s,]+)%s*%)', function(numbers)
            local result = ""
            for num in numbers:gmatch("%d+") do
                local charCode = tonumber(num)
                if charCode and charCode >= 0 and charCode <= 255 then
                    result = result .. string.char(charCode)
                end
            end
            if #result > 0 then
                changeCount = changeCount + 1
                return '"' .. result .. '"'
            end
            return numbers
        end)
        
        -- Decodifica tables de bytes
        decoded = decoded:gsub('{%s*([%d%s,]+)%s*}', function(numbers)
            local result = ""
            local hasChars = false
            for num in numbers:gmatch("%d+") do
                local charCode = tonumber(num)
                if charCode and charCode >= 32 and charCode <= 126 then
                    result = result .. string.char(charCode)
                    hasChars = true
                end
            end
            if hasChars and #result > 2 then
                changeCount = changeCount + 1
                return '"' .. result .. '"'
            end
            return "{" .. numbers .. "}"
        end)
        
        return decoded, changeCount
    end,
    
    -- Simplifica nomes de variáveis ofuscadas
    simplifyVariables = function(self, source)
        local variableMap = {}
        local varCounter = 1
        
        -- Mapeia variáveis upvr/upvw para nomes simples
        local simplified = source
        
        -- Substitui upvr_números por var1, var2, etc
        simplified = simplified:gsub("upvr_(%d+)", function(num)
            local key = "upvr_" .. num
            if not variableMap[key] then
                variableMap[key] = "var" .. varCounter
                varCounter = varCounter + 1
            end
            return variableMap[key]
        end)
        
        -- Substitui upvw_números por val1, val2, etc
        simplified = simplified:gsub("upvw_(%d+)", function(num)
            local key = "upvw_" .. num
            if not variableMap[key] then
                variableMap[key] = "val" .. varCounter
                varCounter = varCounter + 1
            end
            return variableMap[key]
        end)
        
        -- Substitui outras variáveis ofuscadas
        simplified = simplified:gsub("tbl_upvr", "table")
        simplified = simplified:gsub("func_(%d+)_upvr", "func%1")
        simplified = simplified:gsub("arg(%d+)_upvr", "arg%1")
        
        return simplified
    end,
    
    -- Limpa estruturas de controle ofuscadas
    cleanControlStructures = function(self, source)
        local cleaned = source
        
        -- Remove condições dummy
        cleaned = cleaned:gsub("if%s+true%s+then%s*\n", "")
        cleaned = cleaned:gsub("if%s+false%s+then.-end", "")
        
        -- Simplifica loops desnecessários
        cleaned = cleaned:gsub("for%s+_%s*=%s*1%s*,%s*1%s+do\n", "")
        cleaned = cleaned:gsub("while%s+false%s+do.-end", "")
        
        -- Remove blocos vazios
        cleaned = cleaned:gsub("do%s*\n%s*end", "")
        
        return cleaned
    end,
    
    -- Reconstrói estrutura de funções
    reconstructFunctions = function(self, source)
        local reconstructed = source
        
        -- Identifica e limpa funções wrapper desnecessárias
        reconstructed = reconstructed:gsub("local%s+function%s+(%w+)%(%)%s*\n%s*return%s+(%w+)%(%)%s*\n%s*end", 
            function(wrapper, original)
                return "-- Function wrapper removed: " .. wrapper .. " -> " .. original
            end)
        
        -- Remove closures vazios
        reconstructed = reconstructed:gsub("function%(%)%s*\n%s*end", "-- Empty function removed")
        
        return reconstructed
    end,
    
    detect = function(script)
        if not script or not script.Source then 
            return {obfuscated = false, method = "none", confidence = 0}
        end
        
        local source = script.Source
        local signatureCount = 0
        local totalSignatures = #LuraphDecoderModule.luraphSignatures
        
        -- Conta assinaturas encontradas
        for _, signature in pairs(LuraphDecoderModule.luraphSignatures) do
            if source:find(signature) then
                signatureCount = signatureCount + 1
            end
        end
        
        local confidence = signatureCount / totalSignatures
        local isLuraph = signatureCount >= 3
        
        -- Detecção específica de versão
        local version = "unknown"
        if source:find("upvr_") and source:find("upvw_") then
            version = "v1.x"
        elseif source:find("tbl_upvr") then
            version = "v2.x"
        end
        
        return {
            obfuscated = isLuraph,
            method = isLuraph and "luraph_obfuscation" or "none",
            confidence = confidence,
            details = {
                signatures_found = signatureCount,
                total_signatures = totalSignatures,
                estimated_version = version,
                obfuscation_level = signatureCount > 10 and "HIGH" or signatureCount > 5 and "MEDIUM" or "LOW"
            }
        }
    end,
    
    -- Análise avançada de padrões Luraph
    analyzeLuraphPatterns = function(self, source)
        local analysis = {
            variables = {},
            functions = {},
            strings = {},
            complexity = 0
        }
        
        -- Conta variáveis ofuscadas
        for var in source:gmatch("(upvr_%d+)") do
            analysis.variables[var] = (analysis.variables[var] or 0) + 1
        end
        
        -- Conta funções ofuscadas
        for func in source:gmatch("(func_%d+_upvr)") do
            analysis.functions[func] = (analysis.functions[func] or 0) + 1
        end
        
        -- Calcula complexidade
        local varCount = 0
        for _, count in pairs(analysis.variables) do
            varCount = varCount + count
        end
        
        analysis.complexity = varCount + table.getn(analysis.functions) * 2
        
        return analysis
    end
}

return LuraphDecoderModule
