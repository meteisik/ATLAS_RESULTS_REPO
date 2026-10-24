import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonKestrel() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_KESTREL_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonKestrelBase baseObject = new CWE89_P12_V2_CrimsonKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonKestrelBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonKestrelSink extends CWE89_P12_V2_CrimsonKestrelBase {
    public void action(String data) throws SQLException {
        Connection crimsonKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonKestrel");
        Statement crimsonKestrelStatement = null;
        ResultSet crimsonKestrelRows = null;
        try {
            crimsonKestrelStatement = crimsonKestrelConnection.createStatement();
            crimsonKestrelRows = crimsonKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonKestrelRows.getRow());
        } finally {
            if (crimsonKestrelRows != null) {
                crimsonKestrelRows.close();
            }
            if (crimsonKestrelStatement != null) {
                crimsonKestrelStatement.close();
            }
            crimsonKestrelConnection.close();
        }
    }
}
