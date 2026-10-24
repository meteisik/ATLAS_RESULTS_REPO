import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonOrbitSafe {

    public void runCrimsonOrbit() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        CWE89_P12_V2_CrimsonOrbitSafeBase baseObject = new CWE89_P12_V2_CrimsonOrbitSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonOrbitSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonOrbitSafeSink extends CWE89_P12_V2_CrimsonOrbitSafeBase {
    public void action(String data) throws SQLException {
        Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
        Statement crimsonOrbitStatement = null;
        ResultSet crimsonOrbitRows = null;
        try {
            crimsonOrbitStatement = crimsonOrbitConnection.createStatement();
            crimsonOrbitRows = crimsonOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonOrbitRows.getRow());
        } finally {
            if (crimsonOrbitRows != null) {
                crimsonOrbitRows.close();
            }
            if (crimsonOrbitStatement != null) {
                crimsonOrbitStatement.close();
            }
            crimsonOrbitConnection.close();
        }
    }
}
