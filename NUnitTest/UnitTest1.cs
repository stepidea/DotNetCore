using Infrastructure.ParaConvert;
using NUnit.Framework;

namespace NUnitTest
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void Test1()
        {
            string key=RSAHelper.CreateXMLKey();
            Assert.Pass();
        }
    }
}