import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzurePrism {

    public void runAzurePrism() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_PRISM_FILTER");
            break;
        default:
            data = null;
            break;
        }
        CWE89_P12_V2_AzurePrismBase baseObject = new CWE89_P12_V2_AzurePrismSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzurePrismBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzurePrismSink extends CWE89_P12_V2_AzurePrismBase {
    public void action(String data) throws SQLException {
        Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
        Statement azurePrismStatement = null;
        ResultSet azurePrismRows = null;
        try {
            azurePrismStatement = azurePrismConnection.createStatement();
            azurePrismRows = azurePrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azurePrismRows.getRow());
        } finally {
            if (azurePrismRows != null) {
                azurePrismRows.close();
            }
            if (azurePrismStatement != null) {
                azurePrismStatement.close();
            }
            azurePrismConnection.close();
        }
    }
}
