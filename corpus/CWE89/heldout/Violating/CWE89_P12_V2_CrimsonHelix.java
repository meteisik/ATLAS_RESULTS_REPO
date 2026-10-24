import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runCrimsonHelix() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("CRIMSON_HELIX_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonHelixBase baseObject = new CWE89_P12_V2_CrimsonHelixSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonHelixBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonHelixSink extends CWE89_P12_V2_CrimsonHelixBase {
    public void action(String data) throws SQLException {
        Connection crimsonHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHelix");
        Statement crimsonHelixStatement = null;
        ResultSet crimsonHelixRows = null;
        try {
            crimsonHelixStatement = crimsonHelixConnection.createStatement();
            crimsonHelixRows = crimsonHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonHelixRows.getRow());
        } finally {
            if (crimsonHelixRows != null) {
                crimsonHelixRows.close();
            }
            if (crimsonHelixStatement != null) {
                crimsonHelixStatement.close();
            }
            crimsonHelixConnection.close();
        }
    }
}
