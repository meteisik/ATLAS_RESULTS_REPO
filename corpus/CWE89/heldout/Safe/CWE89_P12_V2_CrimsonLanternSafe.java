import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonLantern() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonLanternSafeBase baseObject = new CWE89_P12_V2_CrimsonLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonLanternSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonLanternSafeSink extends CWE89_P12_V2_CrimsonLanternSafeBase {
    public void action(String data) throws SQLException {
        Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
        Statement crimsonLanternStatement = null;
        ResultSet crimsonLanternRows = null;
        try {
            crimsonLanternStatement = crimsonLanternConnection.createStatement();
            crimsonLanternRows = crimsonLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonLanternRows.getRow());
        } finally {
            if (crimsonLanternRows != null) {
                crimsonLanternRows.close();
            }
            if (crimsonLanternStatement != null) {
                crimsonLanternStatement.close();
            }
            crimsonLanternConnection.close();
        }
    }
}
