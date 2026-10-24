import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberAurora {

    public static String data;

    public void runAmberAurora() throws SQLException {
        while (true) {
            data = System.getenv("AMBER_AURORA_FILTER");
            break;
        }
        (new CWE89_P10_V2_AmberAuroraSink()).queryAmberAurora();
    }
}

class CWE89_P10_V2_AmberAuroraSink {
    public void queryAmberAurora() throws SQLException {
        String data = CWE89_P10_V2_AmberAurora.data;
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
