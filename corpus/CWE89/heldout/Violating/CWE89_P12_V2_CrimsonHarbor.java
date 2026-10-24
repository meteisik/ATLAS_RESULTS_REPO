import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonHarbor() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("CRIMSON_HARBOR_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonHarborBase baseObject = new CWE89_P12_V2_CrimsonHarborSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonHarborBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonHarborSink extends CWE89_P12_V2_CrimsonHarborBase {
    public void action(String data) throws SQLException {
        Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
        Statement crimsonHarborStatement = null;
        ResultSet crimsonHarborRows = null;
        try {
            crimsonHarborStatement = crimsonHarborConnection.createStatement();
            crimsonHarborRows = crimsonHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonHarborRows.getRow());
        } finally {
            if (crimsonHarborRows != null) {
                crimsonHarborRows.close();
            }
            if (crimsonHarborStatement != null) {
                crimsonHarborStatement.close();
            }
            crimsonHarborConnection.close();
        }
    }
}
