import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runAmberAurora() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AMBER_AURORA_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberAuroraSink()).queryAmberAurora(dataContainer);
    }
}

class CWE89_P09_V2_AmberAuroraSink {
    public void queryAmberAurora(CWE89_P09_V2_AmberAurora.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
