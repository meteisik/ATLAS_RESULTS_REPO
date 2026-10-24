import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureQuartzSafe {

    public void runAzureQuartz() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        CWE89_P12_V2_AzureQuartzSafeBase baseObject = new CWE89_P12_V2_AzureQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureQuartzSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureQuartzSafeSink extends CWE89_P12_V2_AzureQuartzSafeBase {
    public void action(String data) throws SQLException {
        Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
        Statement azureQuartzStatement = null;
        ResultSet azureQuartzRows = null;
        try {
            azureQuartzStatement = azureQuartzConnection.createStatement();
            azureQuartzRows = azureQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureQuartzRows.getRow());
        } finally {
            if (azureQuartzRows != null) {
                azureQuartzRows.close();
            }
            if (azureQuartzStatement != null) {
                azureQuartzStatement.close();
            }
            azureQuartzConnection.close();
        }
    }
}
