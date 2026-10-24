import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SolarCipher {

    public static String data;

    public void runSolarCipher() throws SQLException {
        data = System.getenv("SOLAR_CIPHER_FILTER");
        (new CWE89_P10_V1_SolarCipherSink()).querySolarCipher();
    }
}

class CWE89_P10_V1_SolarCipherSink {
    public void querySolarCipher() throws SQLException {
        String data = CWE89_P10_V1_SolarCipher.data;
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
