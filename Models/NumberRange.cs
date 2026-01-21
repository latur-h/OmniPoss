namespace OmniPoss.Models
{
    public readonly struct NumberRange(int start, int end)
    {
        public int Start { get; } = start;

        public int End { get; } = end;

        public bool InRange(int num)
        {
            return Start <= num && num <= End;
        }
    }
}
