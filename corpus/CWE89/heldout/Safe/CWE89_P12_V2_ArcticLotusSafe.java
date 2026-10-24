import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runArcticLotus() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticLotusSafeBase baseObject = new CWE89_P12_V2_ArcticLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticLotusSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticLotusSafeSink extends CWE89_P12_V2_ArcticLotusSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        Statement arcticLotusStatement = null;
        ResultSet arcticLotusRows = null;
        try {
            arcticLotusStatement = arcticLotusConnection.createStatement();
            arcticLotusRows = arcticLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLotusRows.getRow());
        } finally {
            if (arcticLotusRows != null) {
                arcticLotusRows.close();
            }
            if (arcticLotusStatement != null) {
                arcticLotusStatement.close();
            }
            arcticLotusConnection.close();
        }
    }
}
