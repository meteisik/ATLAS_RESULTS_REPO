import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonComet() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonCometSafeBase baseObject = new CWE89_P12_V2_CrimsonCometSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonCometSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonCometSafeSink extends CWE89_P12_V2_CrimsonCometSafeBase {
    public void action(String data) throws SQLException {
        Connection crimsonCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonComet");
        Statement crimsonCometStatement = null;
        ResultSet crimsonCometRows = null;
        try {
            crimsonCometStatement = crimsonCometConnection.createStatement();
            crimsonCometRows = crimsonCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonCometRows.getRow());
        } finally {
            if (crimsonCometRows != null) {
                crimsonCometRows.close();
            }
            if (crimsonCometStatement != null) {
                crimsonCometStatement.close();
            }
            crimsonCometConnection.close();
        }
    }
}
