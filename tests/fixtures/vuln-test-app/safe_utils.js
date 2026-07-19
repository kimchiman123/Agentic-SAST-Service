/**
 * 안전한 범용 유틸리티 함수 모음
 * 보안 취약점이 전혀 없는 대용량 파일 시뮬레이션
 */

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    }
}

function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    if (obj instanceof Date) {
        return new Date(obj.getTime());
    }
    if (obj instanceof Array) {
        return obj.reduce((arr, item, i) => {
            arr[i] = deepClone(item);
            return arr;
        }, []);
    }
    if (obj instanceof Object) {
        return Object.keys(obj).reduce((newObj, key) => {
            newObj[key] = deepClone(obj[key]);
            return newObj;
        }, {});
    }
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function parseQueryString(queryString) {
    const params = {};
    const queries = queryString.replace(/^\?/, '').split('&');
    for (let i = 0; i < queries.length; i++) {
        const split = queries[i].split('=');
        params[decodeURIComponent(split[0])] = decodeURIComponent(split[1] || '');
    }
    return params;
}

const mockCityData = [
    { id: 1, name: "Seoul", population: 9700000 },
    { id: 2, name: "Busan", population: 3400000 },
    { id: 3, name: "Incheon", population: 2900000 },
    { id: 4, name: "Daegu", population: 2400000 },
    { id: 5, name: "Daejeon", population: 1500000 },
    { id: 6, name: "Gwangju", population: 1400000 },
    { id: 7, name: "Suwon", population: 1200000 },
    { id: 8, name: "Ulsan", population: 1100000 },
    { id: 9, name: "Changwon", population: 1000000 },
    { id: 10, name: "Goyang", population: 1000000 },
];

function getCitiesByPopulation(minPopulation) {
    return mockCityData.filter(city => city.population >= minPopulation);
}

// 100줄 이상의 더미 데이터 및 반복 함수들로 채워서 파일 크기를 늘림
const DUMMY_CONSTANT_ARRAY = Array.from({ length: 50 }, (_, i) => ({
    index: i,
    val: Math.random() * 100,
    timestamp: Date.now() - i * 1000,
    label: `Item_${i}`
}));

function processDummyData(arr) {
    return arr.map(item => {
        return {
            ...item,
            processed: true,
            newVal: item.val * 2.5
        };
    }).filter(item => item.newVal > 100);
}

module.exports = {
    debounce,
    throttle,
    deepClone,
    generateRandomString,
    parseQueryString,
    getCitiesByPopulation,
    processDummyData,
    DUMMY_CONSTANT_ARRAY
};
