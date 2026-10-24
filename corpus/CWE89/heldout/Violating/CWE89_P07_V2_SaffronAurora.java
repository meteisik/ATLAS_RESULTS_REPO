import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronAurora() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE89_P07_V2_SaffronAuroraSource()).loadSaffronAurora();
        } else {
            data = null;
        }
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        Statement saffronAuroraStatement = null;
        ResultSet saffronAuroraRows = null;
        try {
            saffronAuroraStatement = saffronAuroraConnection.createStatement();
            saffronAuroraRows = saffronAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronAuroraRows.getRow());
        } finally {
            if (saffronAuroraRows != null) {
                saffronAuroraRows.close();
            }
            if (saffronAuroraStatement != null) {
                saffronAuroraStatement.close();
            }
            saffronAuroraConnection.close();
        }
    }
}

class CWE89_P07_V2_SaffronAuroraSource {
    public String loadSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_FILTER");
        return data;
    }
}
