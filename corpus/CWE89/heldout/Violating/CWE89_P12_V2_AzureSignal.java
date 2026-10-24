import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureSignal {

    public void runAzureSignal() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AZURE_SIGNAL_FILTER");
        }
        CWE89_P12_V2_AzureSignalBase baseObject = new CWE89_P12_V2_AzureSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureSignalBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureSignalSink extends CWE89_P12_V2_AzureSignalBase {
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
