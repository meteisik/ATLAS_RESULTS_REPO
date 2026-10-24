import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticHelix {

    public void runArcticHelix() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HELIX_FILTER");
        CWE89_P12_V1_ArcticHelixBase baseObject = new CWE89_P12_V1_ArcticHelixSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticHelixBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticHelixSink extends CWE89_P12_V1_ArcticHelixBase {
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
