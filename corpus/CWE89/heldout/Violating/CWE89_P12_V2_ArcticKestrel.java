import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticKestrel {

    public void runArcticKestrel() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticKestrelBase baseObject = new CWE89_P12_V2_ArcticKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticKestrelBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticKestrelSink extends CWE89_P12_V2_ArcticKestrelBase {
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
