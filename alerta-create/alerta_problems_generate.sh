#!/bin/bash

# Скрипт для генерации команд alerta на основе JSON-файлов
# Автоматически создает команды для всех файлов *_PROBLEM.json

echo "#!/bin/bash" > commands.sh
echo "" >> commands.sh
echo "# Скрипт с командами для отправки алертов" >> commands.sh
echo "# Сгенерирован автоматически $(date)" >> commands.sh
echo "" >> commands.sh

# Функция для обработки JSON-файла и создания команд alerta
process_json_file() {
    local file=$1
    local filename=$(basename "$file")
    
    echo "" >> commands.sh
    echo "# Команды из файла $filename" >> commands.sh
    echo "" >> commands.sh
    
    # Используем jq для парсинга JSON и создания команд
    jq -c '.[]' "$file" | while read -r alert; do
        resource=$(echo $alert | jq -r '.resource')
        event=$(echo $alert | jq -r '.event')
        environment=$(echo $alert | jq -r '.environment')
        severity=$(echo $alert | jq -r '.severity')
        text=$(echo $alert | jq -r '.text')
        group=$(echo $alert | jq -r '.group')
        value=$(echo $alert | jq -r '.value')
        
        # Получаем сервисы как строку с запятыми
        services=$(echo $alert | jq -r '.service | join(",")')
        
        # Получаем теги как отдельные опции --tag
        tags_array=$(echo $alert | jq -r '.tags[]')
        tags_options=""
        for tag in $tags_array; do
            tags_options+="  --tag \"$tag\" \\\n"
        done
        
        # Получаем атрибуты как отдельные опции --attributes key=value
        attrs_array=$(echo $alert | jq -r '.attributes | to_entries[] | "\(.key)=\(.value)"')
        attrs_options="--attributes"
        for attr in $attrs_array; do
            attrs_options+=" \"$attr\" ,"
        done
        
        # Получаем origin
        origin=$(echo $alert | jq -r '.origin')
        
        # Получаем type
        type=$(echo $alert | jq -r '.type')
        
        # Формируем команду alerta
        echo "alerta send \\" >> commands.sh
        echo "  --resource \"$resource\" \\" >> commands.sh
        echo "  --event \"$event\" \\" >> commands.sh
        echo "  --environment \"$environment\" \\" >> commands.sh
        echo "  --severity \"$severity\" \\" >> commands.sh
        echo "  --text \"$text\" \\" >> commands.sh
        echo "  --group \"$group\" \\" >> commands.sh
        echo "  --value \"$value\" \\" >> commands.sh
        echo "  --service \"$services\" \\" >> commands.sh
        echo -e "$tags_options" >> commands.sh
        echo -e "$attrs_options" >> commands.sh
        echo "  --origin \"$origin\" \\" >> commands.sh
        echo "  --type \"$type\"" >> commands.sh
        echo "" >> commands.sh
    done
}

# Обрабатываем все файлы *_PROBLEM.json
for file in *_PROBLEM.json; do
    if [ -f "$file" ]; then
        process_json_file "$file"
    fi
done

echo "Команды сгенерированы и сохранены в файл commands.sh"
echo "Для запуска выполните: bash commands.sh"

# Делаем файл исполняемым
chmod +x commands.sh
