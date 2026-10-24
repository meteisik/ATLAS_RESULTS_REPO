import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_VividAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runVividAurora() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_VividAuroraSafeSink()).queryVividAurora(dataArray);
    }
}

class CWE89_P08_V2_VividAuroraSafeSink {
    public void queryVividAurora(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
