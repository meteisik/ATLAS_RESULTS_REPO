import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureSignalSafe {

    public void runAzureSignal() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        CWE89_P12_V2_AzureSignalSafeBase baseObject = new CWE89_P12_V2_AzureSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureSignalSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureSignalSafeSink extends CWE89_P12_V2_AzureSignalSafeBase {
    public void action(String data) throws SQLException {
        Connection azureSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSignal");
        Statement azureSignalStatement = null;
        ResultSet azureSignalRows = null;
        try {
            azureSignalStatement = azureSignalConnection.createStatement();
            azureSignalRows = azureSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSignalRows.getRow());
        } finally {
            if (azureSignalRows != null) {
                azureSignalRows.close();
            }
            if (azureSignalStatement != null) {
                azureSignalStatement.close();
            }
            azureSignalConnection.close();
        }
    }
}
