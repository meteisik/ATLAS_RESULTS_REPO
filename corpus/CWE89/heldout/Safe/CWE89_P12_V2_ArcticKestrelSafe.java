import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticKestrelSafe {

    public void runArcticKestrel() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticKestrelSafeBase baseObject = new CWE89_P12_V2_ArcticKestrelSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticKestrelSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticKestrelSafeSink extends CWE89_P12_V2_ArcticKestrelSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        Statement arcticKestrelStatement = null;
        ResultSet arcticKestrelRows = null;
        try {
            arcticKestrelStatement = arcticKestrelConnection.createStatement();
            arcticKestrelRows = arcticKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticKestrelRows.getRow());
        } finally {
            if (arcticKestrelRows != null) {
                arcticKestrelRows.close();
            }
            if (arcticKestrelStatement != null) {
                arcticKestrelStatement.close();
            }
            arcticKestrelConnection.close();
        }
    }
}
