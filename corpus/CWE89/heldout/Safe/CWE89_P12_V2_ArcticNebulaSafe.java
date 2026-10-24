import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticNebulaSafe {
    private static boolean privateTrue = true;

    public void runArcticNebula() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticNebulaSafeBase baseObject = new CWE89_P12_V2_ArcticNebulaSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticNebulaSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticNebulaSafeSink extends CWE89_P12_V2_ArcticNebulaSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
        Statement arcticNebulaStatement = null;
        ResultSet arcticNebulaRows = null;
        try {
            arcticNebulaStatement = arcticNebulaConnection.createStatement();
            arcticNebulaRows = arcticNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticNebulaRows.getRow());
        } finally {
            if (arcticNebulaRows != null) {
                arcticNebulaRows.close();
            }
            if (arcticNebulaStatement != null) {
                arcticNebulaStatement.close();
            }
            arcticNebulaConnection.close();
        }
    }
}
