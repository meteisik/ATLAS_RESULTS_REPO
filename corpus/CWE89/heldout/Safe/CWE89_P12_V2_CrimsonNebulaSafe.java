import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonNebulaSafe {

    public void runCrimsonNebula() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        CWE89_P12_V2_CrimsonNebulaSafeBase baseObject = new CWE89_P12_V2_CrimsonNebulaSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonNebulaSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonNebulaSafeSink extends CWE89_P12_V2_CrimsonNebulaSafeBase {
    public void action(String data) throws SQLException {
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        Statement crimsonNebulaStatement = null;
        ResultSet crimsonNebulaRows = null;
        try {
            crimsonNebulaStatement = crimsonNebulaConnection.createStatement();
            crimsonNebulaRows = crimsonNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonNebulaRows.getRow());
        } finally {
            if (crimsonNebulaRows != null) {
                crimsonNebulaRows.close();
            }
            if (crimsonNebulaStatement != null) {
                crimsonNebulaStatement.close();
            }
            crimsonNebulaConnection.close();
        }
    }
}
