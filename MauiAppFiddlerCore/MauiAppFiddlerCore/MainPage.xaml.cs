
using System.Diagnostics.Metrics;
using System.Reflection;

namespace MauiAppFiddlerCore;

public partial class MainPage : ContentPage
{
	int count = 0;

    public MainPage()
	{
        InitializeComponent();
	}

	private void OnCounterClicked(object sender, EventArgs e)
	{

        count = ((App)Application.Current).capturedSessionsCount;


        CounterBtn.Text = $"Captured sessions so far: {count}";

        SemanticScreenReader.Announce(CounterBtn.Text);
	}


}

