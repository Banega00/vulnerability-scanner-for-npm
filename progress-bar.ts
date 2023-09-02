import ProgressBar from 'progress';


const pause = async (duration: number) => new Promise((resolve) => { setTimeout(resolve, duration) });



export async function simulateProgress(step: number = 3) {
    const totalItems = 100;

    const bar = new ProgressBar('[:bar] :percent :etas', {
        total: 100,
        width: 50,
    });
    let progress = 0;
    while (progress < totalItems) {
        // random number between 20 and 200
        const random = Math.floor(Math.random() * 200) + 20;

        await pause(random);

        bar.tick(step)

        if (bar.curr >= bar.total) {
            break;
        }
    }
    bar.terminate();
}