
-- Make sure your variables are all "local". Also, module object name should match the module name.
local example = {}

function example.complexThing(args)
    print("Running complexThing with arguments: "..to_json(args))
end

-- Module requires a return statement
return example
