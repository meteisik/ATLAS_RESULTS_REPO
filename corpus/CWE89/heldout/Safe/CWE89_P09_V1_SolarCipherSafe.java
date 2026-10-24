import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SolarCipherSafe {

    static class Container {
        public String containerOne;
    }

    public void runSolarCipher() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SolarCipherSafeSink()).querySolarCipher(dataContainer);
    }
}

class CWE89_P09_V1_SolarCipherSafeSink {
    public void querySolarCipher(CWE89_P09_V1_SolarCipherSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection solarCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarCipher");
        Statement solarCipherStatement = null;
        ResultSet solarCipherRows = null;
        try {
            solarCipherStatement = solarCipherConnection.createStatement();
            solarCipherRows = solarCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarCipherRows.getRow());
        } finally {
            if (solarCipherRows != null) {
                solarCipherRows.close();
            }
            if (solarCipherStatement != null) {
                solarCipherStatement.close();
            }
            solarCipherConnection.close();
        }
    }
}
