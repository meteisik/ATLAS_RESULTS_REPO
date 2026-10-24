import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberAuroraSafe {

    public static String data;

    public void runAmberAurora() throws SQLException {
        while (true) {
            data = "foo";
            break;
        }
        (new CWE89_P10_V2_AmberAuroraSafeSink()).queryAmberAurora();
    }
}

class CWE89_P10_V2_AmberAuroraSafeSink {
    public void queryAmberAurora() throws SQLException {
        String data = CWE89_P10_V2_AmberAuroraSafe.data;
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        Statement amberAuroraStatement = null;
        ResultSet amberAuroraRows = null;
        try {
            amberAuroraStatement = amberAuroraConnection.createStatement();
            amberAuroraRows = amberAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberAuroraRows.getRow());
        } finally {
            if (amberAuroraRows != null) {
                amberAuroraRows.close();
            }
            if (amberAuroraStatement != null) {
                amberAuroraStatement.close();
            }
            amberAuroraConnection.close();
        }
    }
}
