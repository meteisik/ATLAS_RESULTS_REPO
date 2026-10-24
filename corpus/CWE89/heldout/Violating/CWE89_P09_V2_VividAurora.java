import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VividAurora {
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

    public void runVividAurora() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("VIVID_AURORA_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VividAuroraSink()).queryVividAurora(dataContainer);
    }
}

class CWE89_P09_V2_VividAuroraSink {
    public void queryVividAurora(CWE89_P09_V2_VividAurora.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        Statement vividAuroraStatement = null;
        ResultSet vividAuroraRows = null;
        try {
            vividAuroraStatement = vividAuroraConnection.createStatement();
            vividAuroraRows = vividAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividAuroraRows.getRow());
        } finally {
            if (vividAuroraRows != null) {
                vividAuroraRows.close();
            }
            if (vividAuroraStatement != null) {
                vividAuroraStatement.close();
            }
            vividAuroraConnection.close();
        }
    }
}
