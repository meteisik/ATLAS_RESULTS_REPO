import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticHelixSafe {

    public void runArcticHelix() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ArcticHelixSafeBase baseObject = new CWE89_P12_V1_ArcticHelixSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticHelixSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticHelixSafeSink extends CWE89_P12_V1_ArcticHelixSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        Statement arcticHelixStatement = null;
        ResultSet arcticHelixRows = null;
        try {
            arcticHelixStatement = arcticHelixConnection.createStatement();
            arcticHelixRows = arcticHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHelixRows.getRow());
        } finally {
            if (arcticHelixRows != null) {
                arcticHelixRows.close();
            }
            if (arcticHelixStatement != null) {
                arcticHelixStatement.close();
            }
            arcticHelixConnection.close();
        }
    }
}
