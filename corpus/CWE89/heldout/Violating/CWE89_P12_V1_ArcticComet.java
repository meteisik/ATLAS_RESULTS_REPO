import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticComet {

    public void runArcticComet() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_COMET_FILTER");
        CWE89_P12_V1_ArcticCometBase baseObject = new CWE89_P12_V1_ArcticCometSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticCometBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticCometSink extends CWE89_P12_V1_ArcticCometBase {
    public void action(String data) throws SQLException {
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        Statement arcticCometStatement = null;
        ResultSet arcticCometRows = null;
        try {
            arcticCometStatement = arcticCometConnection.createStatement();
            arcticCometRows = arcticCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticCometRows.getRow());
        } finally {
            if (arcticCometRows != null) {
                arcticCometRows.close();
            }
            if (arcticCometStatement != null) {
                arcticCometStatement.close();
            }
            arcticCometConnection.close();
        }
    }
}
