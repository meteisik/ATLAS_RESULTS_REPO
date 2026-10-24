import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticNebulaSafe {

    public static String data;

    public void runArcticNebula() throws SQLException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE89_P10_V2_ArcticNebulaSafeSink()).queryArcticNebula();
    }
}

class CWE89_P10_V2_ArcticNebulaSafeSink {
    public void queryArcticNebula() throws SQLException {
        String data = CWE89_P10_V2_ArcticNebulaSafe.data;
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
